package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/dpc3354/license-system/internal/common/config"
	"github.com/dpc3354/license-system/internal/common/database"
	"github.com/dpc3354/license-system/internal/common/logging"
	"github.com/dpc3354/license-system/internal/kms"
	"github.com/dpc3354/license-system/internal/kms/crypto"
	"github.com/dpc3354/license-system/internal/kms/keystore"
	"github.com/dpc3354/license-system/internal/kms/models"
)

var (
	configPath = flag.String("config", "config.yaml", "配置文件路径")
	initRoot   = flag.Bool("init-root", false, "初始化 Root Key")
)

func main() {
	flag.Parse()

	// 加载配置
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		// 配置文件不存在时使用默认配置
		fmt.Printf("加载配置失败，使用默认配置: %v\n", err)
		cfg = config.DefaultConfig()
	}

	// 初始化日志
	logger := logging.MustNewLogger(&cfg.Logging)
	defer logger.Sync()

	logger.Info("启动 KMS 服务器",
		zap.String("version", "1.0.0"),
		zap.String("config", *configPath),
	)

	// 初始化或加载 Root Key
	rootKey, err := kms.InitRootKey(cfg.KMS.RootKeyPath)
	if err != nil {
		logger.Fatal("初始化 Root Key 失败", zap.Error(err))
	}
	logger.Info("Root Key 已加载", zap.String("path", cfg.KMS.RootKeyPath))

	// 如果只是初始化 Root Key，则退出
	if *initRoot {
		logger.Info("Root Key 初始化完成，程序退出")
		return
	}

	// 连接数据库（带重试）
	logger.Info("连接数据库...",
		zap.String("host", cfg.Database.Host),
		zap.Int("port", cfg.Database.Port),
	)

	db, err := database.WaitForDB(&cfg.Database, 10, 5*time.Second)
	if err != nil {
		logger.Fatal("连接数据库失败", zap.Error(err))
	}
	defer db.Close()
	logger.Info("数据库连接成功")

	// 初始化 KMS 组件
	cryptoEngine := crypto.NewStandardCryptoEngine()
	store := keystore.NewPostgreSQLKeyStore(db)
	kmsCore := kms.NewKMS(cryptoEngine, store, rootKey)

	logger.Info("KMS 核心组件初始化完成")

	// 创建 HTTP 服务器
	server := NewHTTPServer(cfg, kmsCore, logger)

	// 启动服务器
	go func() {
		addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
		logger.Info("启动 HTTP 服务器", zap.String("addr", addr))

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("HTTP 服务器启动失败", zap.Error(err))
		}
	}()

	// 优雅关闭
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("正在关闭服务器...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("服务器关闭失败", zap.Error(err))
	}

	logger.Info("服务器已关闭")
}

// HTTPServer HTTP 服务器
type HTTPServer struct {
	kms    *kms.KMS
	logger *zap.Logger
	server *http.Server
}

// NewHTTPServer 创建 HTTP 服务器
func NewHTTPServer(cfg *config.Config, kmsCore *kms.KMS, logger *zap.Logger) *http.Server {
	mux := http.NewServeMux()

	handler := &HTTPServer{
		kms:    kmsCore,
		logger: logger,
	}

	// 注册路由
	mux.HandleFunc("/health", handler.HealthCheck)
	mux.HandleFunc("/api/v1/keys", handler.HandleKeys)
	mux.HandleFunc("/api/v1/keys/encrypt", handler.HandleEncrypt)
	mux.HandleFunc("/api/v1/keys/decrypt", handler.HandleDecrypt)
	mux.HandleFunc("/api/v1/keys/sign", handler.HandleSign)
	mux.HandleFunc("/api/v1/keys/verify", handler.HandleVerify)

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)

	return &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}
}

// HealthCheck 健康检查
func (h *HTTPServer) HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
		"time":   time.Now().Format(time.RFC3339),
	})
}

// HandleKeys 处理密钥相关请求
func (h *HTTPServer) HandleKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	switch r.Method {
	case http.MethodPost:
		// 创建密钥
		var req models.CreateKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		key, err := h.kms.CreateKey(ctx, &req)
		if err != nil {
			h.logger.Error("create key failed", zap.Error(err))
			h.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}

		h.respondJSON(w, http.StatusCreated, key)

	default:
		h.respondError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// HandleEncrypt 处理加密请求
func (h *HTTPServer) HandleEncrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.respondError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ctx := r.Context()

	var req models.EncryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := h.kms.Encrypt(ctx, &req)
	if err != nil {
		h.logger.Error("encrypt failed", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, resp)
}

// HandleDecrypt 处理解密请求
func (h *HTTPServer) HandleDecrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.respondError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ctx := r.Context()

	var req models.DecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := h.kms.Decrypt(ctx, &req)
	if err != nil {
		h.logger.Error("decrypt failed", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, resp)
}

// HandleSign 处理签名请求
func (h *HTTPServer) HandleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.respondError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ctx := r.Context()

	var req models.SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := h.kms.Sign(ctx, &req)
	if err != nil {
		h.logger.Error("sign failed", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, resp)
}

// HandleVerify 处理验证签名请求
func (h *HTTPServer) HandleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.respondError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ctx := r.Context()

	var req models.VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := h.kms.Verify(ctx, &req)
	if err != nil {
		h.logger.Error("verify failed", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, resp)
}

// respondJSON 返回 JSON 响应
func (h *HTTPServer) respondJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

// respondError 返回错误响应
func (h *HTTPServer) respondError(w http.ResponseWriter, statusCode int, message string) {
	h.respondJSON(w, statusCode, map[string]string{
		"error": message,
	})
}
