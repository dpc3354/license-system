package http

import (
	"encoding/json"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/dpc3354/license-system/internal/kms"
	"github.com/dpc3354/license-system/internal/kms/models"
)

// Handler HTTP API 处理器
type Handler struct {
	kms    *kms.KMS
	logger *zap.Logger
}

// NewHandler 创建 HTTP 处理器
func NewHandler(kmsCore *kms.KMS, logger *zap.Logger) *Handler {
	return &Handler{
		kms:    kmsCore,
		logger: logger,
	}
}

// HealthCheck 健康检查
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	h.respondJSON(w, http.StatusOK, map[string]string{
		"status": "healthy",
		"time":   time.Now().Format(time.RFC3339),
	})
}

// CreateKey 创建密钥
func (h *Handler) CreateKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.respondError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ctx := r.Context()

	var req models.CreateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// 验证请求参数
	if err := h.validateCreateKeyRequest(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	key, err := h.kms.CreateKey(ctx, &req)
	if err != nil {
		h.logger.Error("create key failed",
			zap.Error(err),
			zap.String("tenant_id", req.TenantID),
		)
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.logger.Info("key created",
		zap.String("key_id", key.KeyID),
		zap.String("tenant_id", key.TenantID),
		zap.String("algorithm", string(key.Algorithm)),
	)

	h.respondJSON(w, http.StatusCreated, key)
}

// Encrypt 加密
func (h *Handler) Encrypt(w http.ResponseWriter, r *http.Request) {
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

	if req.KeyID == "" {
		h.respondError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	if len(req.Plaintext) == 0 {
		h.respondError(w, http.StatusBadRequest, "plaintext is required")
		return
	}

	resp, err := h.kms.Encrypt(ctx, &req)
	if err != nil {
		h.logger.Error("encrypt failed",
			zap.Error(err),
			zap.String("key_id", req.KeyID),
		)
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, resp)
}

// Decrypt 解密
func (h *Handler) Decrypt(w http.ResponseWriter, r *http.Request) {
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

	if req.KeyID == "" {
		h.respondError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	if len(req.Ciphertext) == 0 {
		h.respondError(w, http.StatusBadRequest, "ciphertext is required")
		return
	}

	resp, err := h.kms.Decrypt(ctx, &req)
	if err != nil {
		h.logger.Error("decrypt failed",
			zap.Error(err),
			zap.String("key_id", req.KeyID),
		)
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, resp)
}

// Sign 签名
func (h *Handler) Sign(w http.ResponseWriter, r *http.Request) {
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

	if req.KeyID == "" {
		h.respondError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	if len(req.Message) == 0 {
		h.respondError(w, http.StatusBadRequest, "message is required")
		return
	}

	resp, err := h.kms.Sign(ctx, &req)
	if err != nil {
		h.logger.Error("sign failed",
			zap.Error(err),
			zap.String("key_id", req.KeyID),
		)
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, resp)
}

// Verify 验证签名
func (h *Handler) Verify(w http.ResponseWriter, r *http.Request) {
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

	if req.KeyID == "" {
		h.respondError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	if len(req.Message) == 0 {
		h.respondError(w, http.StatusBadRequest, "message is required")
		return
	}

	if len(req.Signature) == 0 {
		h.respondError(w, http.StatusBadRequest, "signature is required")
		return
	}

	resp, err := h.kms.Verify(ctx, &req)
	if err != nil {
		h.logger.Error("verify failed",
			zap.Error(err),
			zap.String("key_id", req.KeyID),
		)
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, resp)
}

// GetKey 获取密钥信息（不包含密钥材料）
func (h *Handler) GetKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.respondError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// TODO: 从 URL 路径中提取 key_id
	// 暂时从查询参数获取
	keyID := r.URL.Query().Get("key_id")
	if keyID == "" {
		h.respondError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	// TODO: 实现 GetKey 方法
	h.respondError(w, http.StatusNotImplemented, "not implemented yet")
}

// ListKeys 列出密钥
func (h *Handler) ListKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.respondError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// TODO: 从查询参数获取过滤条件
	// tenantID := r.URL.Query().Get("tenant_id")

	// TODO: 实现 ListKeys 方法
	h.respondError(w, http.StatusNotImplemented, "not implemented yet")
}

// RotateKey 轮换密钥
func (h *Handler) RotateKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.respondError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req models.RotateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.KeyID == "" {
		h.respondError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	ctx := r.Context()

	resp, err := h.kms.RotateKey(ctx, req.KeyID)
	if err != nil {
		h.logger.Error("rotate key failed",
			zap.Error(err),
			zap.String("key_id", req.KeyID),
		)
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, resp)
}

// DisableKey 禁用密钥
func (h *Handler) DisableKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.respondError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	keyID := r.URL.Query().Get("key_id")
	if keyID == "" {
		h.respondError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	ctx := r.Context()

	if err := h.kms.DisableKey(ctx, keyID); err != nil {
		h.logger.Error("disable key failed",
			zap.Error(err),
			zap.String("key_id", keyID),
		)
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]string{
		"message": "key disabled successfully",
		"key_id":  keyID,
	})
}

// EnableKey 启用密钥
func (h *Handler) EnableKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.respondError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	keyID := r.URL.Query().Get("key_id")
	if keyID == "" {
		h.respondError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	ctx := r.Context()

	if err := h.kms.EnableKey(ctx, keyID); err != nil {
		h.logger.Error("enable key failed",
			zap.Error(err),
			zap.String("key_id", keyID),
		)
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]string{
		"message": "key enabled successfully",
		"key_id":  keyID,
	})
}

// validateCreateKeyRequest 验证创建密钥请求
func (h *Handler) validateCreateKeyRequest(req *models.CreateKeyRequest) error {
	if req.TenantID == "" {
		return &ValidationError{Field: "tenant_id", Message: "is required"}
	}

	if req.Algorithm == "" {
		return &ValidationError{Field: "algorithm", Message: "is required"}
	}

	if req.Usage == "" {
		return &ValidationError{Field: "usage", Message: "is required"}
	}

	// 验证算法和用途的组合
	switch req.Usage {
	case models.KeyUsageEncryptDecrypt:
		if req.Algorithm != models.AlgorithmAES256GCM && req.Algorithm != models.AlgorithmAES128GCM {
			return &ValidationError{
				Field:   "algorithm",
				Message: "must be AES_256_GCM or AES_128_GCM for ENCRYPT_DECRYPT usage",
			}
		}
	case models.KeyUsageSignVerify:
		if req.Algorithm != models.AlgorithmRSA2048 &&
			req.Algorithm != models.AlgorithmRSA4096 &&
			req.Algorithm != models.AlgorithmECDSAP256 &&
			req.Algorithm != models.AlgorithmECDSAP384 {
			return &ValidationError{
				Field:   "algorithm",
				Message: "must be RSA or ECDSA for SIGN_VERIFY usage",
			}
		}
	}

	return nil
}

// respondJSON 返回 JSON 响应
func (h *Handler) respondJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode response", zap.Error(err))
	}
}

// respondError 返回错误响应
func (h *Handler) respondError(w http.ResponseWriter, statusCode int, message string) {
	h.respondJSON(w, statusCode, map[string]interface{}{
		"error":     message,
		"status":    statusCode,
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// ValidationError 验证错误
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return e.Field + " " + e.Message
}
