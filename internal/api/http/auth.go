package http

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/dpc3354/license-system/internal/common/ctxkeys"
	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"
)

// APIKey 表示一个 API 密钥
type APIKey struct {
	ID        string
	Name      string // 密钥名称（如 "license-server", "monitoring"）
	KeyHash   string // SHA256(api_key)
	CreatedAt time.Time
	ExpiresAt *time.Time
	Enabled   bool
}

// APIKeyStore API 密钥存储接口
type APIKeyStore interface {
	GetByKeyHash(keyHash string) (*APIKey, error)
}

type PostgresSQLAPIKeyStore struct {
	db *sqlx.DB
}

// NewPostgresSQLAPIKeyStore 创建 PostgreSQL API Key 存储
func NewPostgresSQLAPIKeyStore(db *sqlx.DB) *PostgresSQLAPIKeyStore {
	return &PostgresSQLAPIKeyStore{db: db}
}

// GetByKeyHash 根据密钥哈希获取 API Key
func (s *PostgresSQLAPIKeyStore) GetByKeyHash(keyHash string) (*APIKey, error) {
	var key APIKey
	query := `
		SELECT id, name, key_hash, enabled, created_at, expires_at
		FROM api_keys
		WHERE key_hash = $1 AND enabled = true
	`

	err := s.db.QueryRow(query, keyHash).Scan(
		&key.ID,
		&key.Name,
		&key.KeyHash,
		&key.Enabled,
		&key.CreatedAt,
		&key.ExpiresAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil // 未找到密钥
	}
	if err != nil {
		return nil, err
	}

	// 异步更新最后使用时间（不阻塞主流程）
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		updateQuery := `UPDATE api_keys SET last_used_at = $1 WHERE id = $2`
		_, _ = s.db.ExecContext(ctx, updateQuery, time.Now(), key.ID)
	}()

	return &key, nil
}

// APIKeyAuthMiddleware API Key 认证中间件
func APIKeyAuthMiddleware(store APIKeyStore, logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 跳过健康检查
			if r.URL.Path == "/health" {
				next.ServeHTTP(w, r)
				return
			}

			// 从 Authorization 头提取 API Key
			// 格式: "Bearer kms_xxx..." 或 "ApiKey kms_xxx..."
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				logger.Warn("missing authorization header",
					zap.String("path", r.URL.Path),
					zap.String("remote_addr", r.RemoteAddr),
				)
				respondUnauthorized(w, "missing authorization header")
				return
			}

			// 提取 API Key
			var apiKey string
			if strings.HasPrefix(authHeader, "Bearer ") {
				apiKey = strings.TrimPrefix(authHeader, "Bearer ")
			} else if strings.HasPrefix(authHeader, "ApiKey ") {
				apiKey = strings.TrimPrefix(authHeader, "ApiKey ")
			} else {
				respondUnauthorized(w, "invalid authorization format")
				return
			}

			// 验证 API Key
			keyHash := hashAPIKey(apiKey)
			key, err := store.GetByKeyHash(keyHash)
			if err != nil {
				logger.Error("failed to lookup api key", zap.Error(err))
				respondUnauthorized(w, "internal error")
				return
			}

			if key == nil {
				logger.Warn("invalid api key",
					zap.String("path", r.URL.Path),
					zap.String("remote_addr", r.RemoteAddr),
				)
				respondUnauthorized(w, "invalid api key")
				return
			}

			// 检查密钥是否启用
			if !key.Enabled {
				logger.Warn("disabled api key",
					zap.String("key_name", key.Name),
				)
				respondUnauthorized(w, "api key disabled")
				return
			}

			// 检查是否过期
			if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
				logger.Warn("expired api key",
					zap.String("key_name", key.Name),
				)
				respondUnauthorized(w, "api key expired")
				return
			}

			// 认证成功，将用户信息存入 context
			ctx := context.WithValue(r.Context(), ctxkeys.UserKey, key.Name)
			ctx = context.WithValue(ctx, ctxkeys.UserID, key.ID)

			logger.Debug("api key authenticated",
				zap.String("key_name", key.Name),
				zap.String("path", r.URL.Path),
			)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// hashAPIKey 计算 API Key 的 SHA256 哈希
func hashAPIKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

// respondUnauthorized 返回 401 未授权响应
func respondUnauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="KMS API"`)
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(`{"error":"` + message + `"}`))
}
