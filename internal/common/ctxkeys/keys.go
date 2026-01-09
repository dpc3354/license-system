package ctxkeys

import "context"

// ContextKey context 键类型
type ContextKey string

// 所有 context keys 的定义
const (
	// 请求相关
	ClientIP  ContextKey = "client_ip"
	UserAgent ContextKey = "user_agent"
	RequestID ContextKey = "request_id"

	// 用户相关
	UserKey  ContextKey = "user"
	UserID   ContextKey = "user_id"
	Username ContextKey = "username"
	TenantID ContextKey = "tenant_id"

	// 权限相关
	Roles       ContextKey = "roles"
	Permissions ContextKey = "permissions"
)

// 辅助函数
func GetClientIP(ctx context.Context) string {
	if ip, ok := ctx.Value(ClientIP).(string); ok {
		return ip
	}
	return ""
}

func GetUser(ctx context.Context) string {
	if user, ok := ctx.Value(UserKey).(string); ok {
		return user
	}
	return ""
}

func GetUserID(ctx context.Context) string {
	if id, ok := ctx.Value(UserID).(string); ok {
		return id
	}
	return ""
}
