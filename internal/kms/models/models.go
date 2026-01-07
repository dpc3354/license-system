package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

// KeyAlgorithm 密钥算法类型
type KeyAlgorithm string

const (
	AlgorithmRSA2048   KeyAlgorithm = "RSA_2048"
	AlgorithmRSA4096   KeyAlgorithm = "RSA_4096"
	AlgorithmAES256GCM KeyAlgorithm = "AES_256_GCM"
	AlgorithmAES128GCM KeyAlgorithm = "AES_128_GCM"
	AlgorithmECDSAP256 KeyAlgorithm = "ECDSA_P256"
	AlgorithmECDSAP384 KeyAlgorithm = "ECDSA_P384"
)

// KeyState 密钥状态
type KeyState string

const (
	KeyStateEnabled         KeyState = "ENABLED"
	KeyStateDisabled        KeyState = "DISABLED"
	KeyStatePendingDeletion KeyState = "PENDING_DELETION"
	KeyStateDeleted         KeyState = "DELETED"
)

// KeyUsage 密钥用途
type KeyUsage string

const (
	KeyUsageEncryptDecrypt KeyUsage = "ENCRYPT_DECRYPT"
	KeyUsageSignVerify     KeyUsage = "SIGN_VERIFY"
)

// EncryptedKeyMaterial 加密后的密钥材料
type EncryptedKeyMaterial struct {
	EncryptedData []byte `json:"encrypted_data"` // 加密后的密钥数据
	IV            []byte `json:"iv"`             // 初始化向量
	Tag           []byte `json:"tag"`            // GCM 认证标签
	Algorithm     string `json:"algorithm"`      // 加密算法标识
}

// Scan 实现 sql.Scanner 接口
func (e *EncryptedKeyMaterial) Scan(value interface{}) error {
	if value == nil {
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to unmarshal EncryptedKeyMaterial: %v", value)
	}

	return json.Unmarshal(bytes, e)
}

// Value 实现 driver.Valuer 接口
func (e EncryptedKeyMaterial) Value() (driver.Value, error) {
	return json.Marshal(e)
}

// KeyMetadata 密钥元数据
type KeyMetadata map[string]string

// Scan 实现 sql.Scanner 接口
func (m *KeyMetadata) Scan(value interface{}) error {
	if value == nil {
		*m = make(KeyMetadata)
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to unmarshal KeyMetadata: %v", value)
	}

	return json.Unmarshal(bytes, m)
}

// Value 实现 driver.Valuer 接口
func (m KeyMetadata) Value() (driver.Value, error) {
	if m == nil {
		return json.Marshal(make(map[string]string))
	}
	return json.Marshal(m)
}

// MasterKey 主密钥（存储在数据库中）
type MasterKey struct {
	ID                string               `db:"id" json:"id"`
	KeyID             string               `db:"key_id" json:"key_id"` // 对外暴露的密钥标识
	TenantID          string               `db:"tenant_id" json:"tenant_id"`
	Algorithm         KeyAlgorithm         `db:"algorithm" json:"algorithm"`
	Usage             KeyUsage             `db:"usage" json:"usage"`
	EncryptedMaterial EncryptedKeyMaterial `db:"encrypted_key_material" json:"-"` // 不在 JSON 中暴露
	State             KeyState             `db:"state" json:"state"`
	Version           int                  `db:"version" json:"version"`
	Metadata          KeyMetadata          `db:"metadata" json:"metadata"`
	RotationSchedule  *time.Duration       `db:"rotation_schedule" json:"rotation_schedule,omitempty"`
	CreatedAt         time.Time            `db:"created_at" json:"created_at"`
	UpdatedAt         time.Time            `db:"updated_at" json:"updated_at"`
	DeletedAt         *time.Time           `db:"deleted_at" json:"deleted_at,omitempty"`
}

// KeyVersion 密钥版本（支持密钥轮换）
type KeyVersion struct {
	ID                string               `db:"id" json:"id"`
	MasterKeyID       string               `db:"master_key_id" json:"master_key_id"`
	VersionNumber     int                  `db:"version_number" json:"version_number"`
	EncryptedMaterial EncryptedKeyMaterial `db:"encrypted_key_material" json:"-"`
	State             KeyState             `db:"state" json:"state"`
	CreatedAt         time.Time            `db:"created_at" json:"created_at"`
	DeprecatedAt      *time.Time           `db:"deprecated_at" json:"deprecated_at,omitempty"`
}

// KeyOperation 密钥操作记录（审计日志）
type KeyOperation struct {
	ID           int64     `db:"id" json:"id"`
	KeyID        string    `db:"key_id" json:"key_id"`
	Operation    string    `db:"operation" json:"operation"` // ENCRYPT, DECRYPT, SIGN, VERIFY, ROTATE, etc.
	Requestor    string    `db:"requestor" json:"requestor"` // 请求者标识
	IPAddress    string    `db:"ip_address" json:"ip_address,omitempty"`
	Success      bool      `db:"success" json:"success"`
	ErrorMessage string    `db:"error_message" json:"error_message,omitempty"`
	Timestamp    time.Time `db:"timestamp" json:"timestamp"`
}

// KeyPolicy 密钥访问策略
type KeyPolicy struct {
	ID         string    `db:"id" json:"id"`
	KeyID      string    `db:"key_id" json:"key_id"`
	Principal  string    `db:"principal" json:"principal"` // 用户/服务标识
	Actions    []string  `db:"actions" json:"actions"`     // 允许的操作
	Effect     string    `db:"effect" json:"effect"`       // ALLOW / DENY
	Conditions string    `db:"conditions" json:"conditions,omitempty"`
	CreatedAt  time.Time `db:"created_at" json:"created_at"`
}

// KeyAlias 密钥别名
type KeyAlias struct {
	ID        string    `db:"id" json:"id"`
	AliasName string    `db:"alias_name" json:"alias_name"`
	KeyID     string    `db:"key_id" json:"key_id"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

// CreateKeyRequest 创建密钥请求
type CreateKeyRequest struct {
	TenantID         string            `json:"tenant_id"`
	Algorithm        KeyAlgorithm      `json:"algorithm"`
	Usage            KeyUsage          `json:"usage"`
	Description      string            `json:"description"`
	Tags             map[string]string `json:"tags,omitempty"`
	RotationSchedule *time.Duration    `json:"rotation_schedule,omitempty"`
}

// EncryptRequest 加密请求
type EncryptRequest struct {
	KeyID             string            `json:"key_id"`
	Plaintext         []byte            `json:"plaintext"`
	EncryptionContext map[string]string `json:"encryption_context,omitempty"` // AAD
}

// EncryptResponse 加密响应
type EncryptResponse struct {
	KeyID      string `json:"key_id"`
	Ciphertext []byte `json:"ciphertext"`
	Version    int    `json:"version"`
}

// DecryptRequest 解密请求
type DecryptRequest struct {
	KeyID             string            `json:"key_id"`
	Ciphertext        []byte            `json:"ciphertext"`
	EncryptionContext map[string]string `json:"encryption_context,omitempty"`
}

// DecryptResponse 解密响应
type DecryptResponse struct {
	KeyID     string `json:"key_id"`
	Plaintext []byte `json:"plaintext"`
	Version   int    `json:"version"`
}

// SignRequest 签名请求
type SignRequest struct {
	KeyID   string `json:"key_id"`
	Message []byte `json:"message"`
}

// SignResponse 签名响应
type SignResponse struct {
	KeyID     string `json:"key_id"`
	Signature []byte `json:"signature"`
	Version   int    `json:"version"`
}

// VerifyRequest 验证签名请求
type VerifyRequest struct {
	KeyID     string `json:"key_id"`
	Message   []byte `json:"message"`
	Signature []byte `json:"signature"`
}

// VerifyResponse 验证签名响应
type VerifyResponse struct {
	KeyID   string `json:"key_id"`
	Valid   bool   `json:"valid"`
	Version int    `json:"version"`
}
