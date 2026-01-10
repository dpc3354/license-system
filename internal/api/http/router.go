package http

import (
	"net/http"

	"go.uber.org/zap"

	"github.com/dpc3354/license-system/internal/kms"
)

// Router HTTP 路由器
type Router struct {
	mux     *http.ServeMux
	handler *Handler
	logger  *zap.Logger
}

// NewRouter 创建路由器
func NewRouter(kmsCore *kms.KMS, logger *zap.Logger) *Router {
	handler := NewHandler(kmsCore, logger)

	return &Router{
		mux:     http.NewServeMux(),
		handler: handler,
		logger:  logger,
	}
}

// Setup 设置路由
func (r *Router) Setup() *http.ServeMux {
	// 健康检查
	r.mux.HandleFunc("/health", r.handler.HealthCheck)

	// API v1 路由
	r.mux.HandleFunc("/api/v1/keys", r.handleKeys)
	r.mux.HandleFunc("/api/v1/keys/encrypt", r.handler.Encrypt)
	r.mux.HandleFunc("/api/v1/keys/decrypt", r.handler.Decrypt)
	r.mux.HandleFunc("/api/v1/keys/sign", r.handler.Sign)
	r.mux.HandleFunc("/api/v1/keys/verify", r.handler.Verify)
	r.mux.HandleFunc("/api/v1/keys/rotate", r.handler.RotateKey)
	r.mux.HandleFunc("/api/v1/keys/disable", r.handler.DisableKey)
	r.mux.HandleFunc("/api/v1/keys/enable", r.handler.EnableKey)
	r.mux.HandleFunc("/api/v1/generate-data-key", r.handler.GenerateDataKey) // 信封加密
	r.mux.HandleFunc("/api/v1/decrypt-data-key", r.handler.DecryptDataKey)   // 信封加密：解密 DEK

	return r.mux
}

// handleKeys 处理 /api/v1/keys 路由（支持多种方法）
func (r *Router) handleKeys(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodPost:
		r.handler.CreateKey(w, req)
	case http.MethodGet:
		// 判断是获取单个密钥还是列表
		if req.URL.Query().Get("key_id") != "" {
			r.handler.GetKey(w, req)
		} else {
			r.handler.ListKeys(w, req)
		}
	default:
		r.handler.respondError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// ServeHTTP 实现 http.Handler 接口
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}

// WithMiddleware 添加中间件
func (r *Router) WithMiddleware(middleware func(http.Handler) http.Handler) http.Handler {
	return middleware(r.mux)
}
