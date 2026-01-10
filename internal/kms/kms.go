package kms

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dpc3354/license-system/internal/common/ctxkeys"
	"github.com/dpc3354/license-system/internal/kms/crypto"
	"github.com/dpc3354/license-system/internal/kms/keystore"
	"github.com/dpc3354/license-system/internal/kms/models"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// KMS 核心服务
type KMS struct {
	crypto  crypto.CryptoEngine
	store   keystore.KeyStore
	rootKey []byte // Root Key，用于加密 Master Keys
	logger  *zap.Logger
}

// NewKMS 创建 KMS 实例
func NewKMS(cryptoEngine crypto.CryptoEngine, store keystore.KeyStore, rootKey []byte, logger *zap.Logger) *KMS {
	return &KMS{
		crypto:  cryptoEngine,
		store:   store,
		rootKey: rootKey,
		logger:  logger,
	}
}

// CreateKey 创建新密钥
func (k *KMS) CreateKey(ctx context.Context, req *models.CreateKeyRequest) (*models.MasterKey, error) {
	// 生成密钥材料
	var keyMaterial []byte
	var err error

	switch req.Usage {
	case models.KeyUsageEncryptDecrypt:
		// 对称密钥
		keyMaterial, err = k.crypto.GenerateSymmetricKey(req.Algorithm)
		if err != nil {
			return nil, fmt.Errorf("generate symmetric key: %w", err)
		}

	case models.KeyUsageSignVerify:
		// 非对称密钥
		privateKey, _, err := k.crypto.GenerateKeyPair(req.Algorithm)
		if err != nil {
			return nil, fmt.Errorf("generate key pair: %w", err)
		}
		keyMaterial = privateKey

	default:
		return nil, fmt.Errorf("unsupported key usage: %s", req.Usage)
	}

	// 使用 Root Key 加密密钥材料
	encryptedMaterial, err := k.encryptKeyMaterial(keyMaterial)
	if err != nil {
		crypto.ClearBytes(keyMaterial)
		return nil, fmt.Errorf("encrypt key material: %w", err)
	}

	// 清除明文密钥材料
	crypto.ClearBytes(keyMaterial)

	// 构建密钥元数据
	metadata := models.KeyMetadata{
		"description": req.Description,
	}
	for k, v := range req.Tags {
		metadata[k] = v
	}

	// 创建 Master Key 对象
	now := time.Now()
	masterKey := &models.MasterKey{
		ID:                uuid.New().String(),
		KeyID:             generateKeyID(),
		TenantID:          req.TenantID,
		Algorithm:         req.Algorithm,
		Usage:             req.Usage,
		EncryptedMaterial: encryptedMaterial,
		State:             models.KeyStateEnabled,
		Version:           1,
		Metadata:          metadata,
		RotationSchedule:  req.RotationSchedule,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	// 保存到数据库
	if err := k.store.SaveKey(ctx, masterKey); err != nil {
		return nil, fmt.Errorf("save key: %w", err)
	}

	// 创建秘钥版本
	initialVersion := &models.KeyVersion{
		ID:                uuid.New().String(),
		MasterKeyID:       masterKey.ID,
		VersionNumber:     1,
		EncryptedMaterial: encryptedMaterial,
		State:             models.KeyStateEnabled,
		CreatedAt:         now,
	}

	if err := k.store.SaveKeyVersion(ctx, initialVersion); err != nil {
		return nil, fmt.Errorf("save key version: %w", err)
	}

	// 记录审计日志
	k.logOperation(ctx, masterKey.KeyID, "CREATE_KEY", true, "")

	return masterKey, nil
}

// Encrypt 加密数据
func (k *KMS) Encrypt(ctx context.Context, req *models.EncryptRequest) (*models.EncryptResponse, error) {
	// 加载最新密钥
	key, err := k.store.GetKey(ctx, req.KeyID)
	latestVersion, err := k.store.GetLatestKeyVersion(ctx, req.KeyID)
	if err != nil {
		k.logOperation(ctx, req.KeyID, "ENCRYPT", false, err.Error())
		return nil, fmt.Errorf("get key: %w", err)
	}

	// 检查密钥状态
	if key.State != models.KeyStateEnabled {
		err := fmt.Errorf("key is not enabled: %s", key.State)
		k.logOperation(ctx, req.KeyID, "ENCRYPT", false, err.Error())
		return nil, err
	}

	// 检查密钥用途
	if key.Usage != models.KeyUsageEncryptDecrypt {
		err := fmt.Errorf("key is not for encryption: %s", key.Usage)
		k.logOperation(ctx, req.KeyID, "ENCRYPT", false, err.Error())
		return nil, err
	}

	// 解密密钥材料
	keyMaterial, err := k.decryptKeyMaterial(latestVersion.EncryptedMaterial)
	if err != nil {
		k.logOperation(ctx, req.KeyID, "ENCRYPT", false, err.Error())
		return nil, fmt.Errorf("decrypt key material: %w", err)
	}
	defer crypto.ClearBytes(keyMaterial)

	// 将 EncryptionContext 序列化为 AAD (Additional Authenticated Data)
	aad, err := serializeContext(req.EncryptionContext)
	if err != nil {
		k.logOperation(ctx, req.KeyID, "ENCRYPT", false, err.Error())
		return nil, fmt.Errorf("serialize context: %w", err)
	}

	// 执行加密
	ciphertext, iv, tag, err := k.crypto.EncryptAESGCM(keyMaterial, req.Plaintext, aad)
	if err != nil {
		k.logOperation(ctx, req.KeyID, "ENCRYPT", false, err.Error())
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	// 组合密文格式: version(1 byte) + iv + ciphertext + tag
	result := make([]byte, 1+len(iv)+len(ciphertext)+len(tag))
	result[0] = byte(key.Version)
	copy(result[1:], iv)
	copy(result[1+len(iv):], ciphertext)
	copy(result[1+len(iv)+len(ciphertext):], tag)

	k.logOperation(ctx, req.KeyID, "ENCRYPT", true, "")

	return &models.EncryptResponse{
		KeyID:      key.KeyID,
		Ciphertext: result,
		Version:    key.Version,
	}, nil
}

// Decrypt 解密数据
func (k *KMS) Decrypt(ctx context.Context, req *models.DecryptRequest) (*models.DecryptResponse, error) {
	// 加载密钥
	key, err := k.store.GetKey(ctx, req.KeyID)
	if err != nil {
		k.logOperation(ctx, req.KeyID, "DECRYPT", false, err.Error())
		return nil, fmt.Errorf("get key: %w", err)
	}

	// 检查密钥用途
	if key.Usage != models.KeyUsageEncryptDecrypt {
		err := fmt.Errorf("key is not for decryption: %s", key.Usage)
		k.logOperation(ctx, req.KeyID, "DECRYPT", false, err.Error())
		return nil, err
	}

	// 解析密文格式
	if len(req.Ciphertext) < 30 { // 最小长度检查
		err := fmt.Errorf("invalid ciphertext format")
		k.logOperation(ctx, req.KeyID, "DECRYPT", false, err.Error())
		return nil, err
	}

	version := int(req.Ciphertext[0])
	ivSize := 12  // GCM nonce size
	tagSize := 16 // GCM tag size

	iv := req.Ciphertext[1 : 1+ivSize]
	ciphertext := req.Ciphertext[1+ivSize : len(req.Ciphertext)-tagSize]
	tag := req.Ciphertext[len(req.Ciphertext)-tagSize:]

	// 解密密钥材料
	keyMaterial, err := k.decryptKeyMaterial(key.EncryptedMaterial)
	if err != nil {
		k.logOperation(ctx, req.KeyID, "DECRYPT", false, err.Error())
		return nil, fmt.Errorf("decrypt key material: %w", err)
	}
	defer crypto.ClearBytes(keyMaterial)

	// 将 EncryptionContext 序列化为 AAD
	aad, err := serializeContext(req.EncryptionContext)
	if err != nil {
		k.logOperation(ctx, req.KeyID, "DECRYPT", false, err.Error())
		return nil, fmt.Errorf("serialize context: %w", err)
	}

	// 执行解密
	plaintext, err := k.crypto.DecryptAESGCM(keyMaterial, ciphertext, iv, tag, aad)
	if err != nil {
		k.logOperation(ctx, req.KeyID, "DECRYPT", false, err.Error())
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	k.logOperation(ctx, req.KeyID, "DECRYPT", true, "")

	return &models.DecryptResponse{
		KeyID:     key.KeyID,
		Plaintext: plaintext,
		Version:   version,
	}, nil
}

// Sign 签名
func (k *KMS) Sign(ctx context.Context, req *models.SignRequest) (*models.SignResponse, error) {
	// 加载密钥
	key, err := k.store.GetKey(ctx, req.KeyID)
	if err != nil {
		k.logOperation(ctx, req.KeyID, "SIGN", false, err.Error())
		return nil, fmt.Errorf("get key: %w", err)
	}

	// 检查密钥状态
	if key.State != models.KeyStateEnabled {
		err := fmt.Errorf("key is not enabled: %s", key.State)
		k.logOperation(ctx, req.KeyID, "SIGN", false, err.Error())
		return nil, err
	}

	// 检查密钥用途
	if key.Usage != models.KeyUsageSignVerify {
		err := fmt.Errorf("key is not for signing: %s", key.Usage)
		k.logOperation(ctx, req.KeyID, "SIGN", false, err.Error())
		return nil, err
	}

	// 解密私钥
	privateKey, err := k.decryptKeyMaterial(key.EncryptedMaterial)
	if err != nil {
		k.logOperation(ctx, req.KeyID, "SIGN", false, err.Error())
		return nil, fmt.Errorf("decrypt private key: %w", err)
	}
	defer crypto.ClearBytes(privateKey)

	// 根据算法选择签名方法
	var signature []byte
	switch key.Algorithm {
	case models.AlgorithmRSA2048, models.AlgorithmRSA4096:
		signature, err = k.crypto.SignRSA(privateKey, req.Message)
	case models.AlgorithmECDSAP256, models.AlgorithmECDSAP384:
		signature, err = k.crypto.SignECDSA(privateKey, req.Message)
	default:
		err = fmt.Errorf("unsupported signing algorithm: %s", key.Algorithm)
	}

	if err != nil {
		k.logOperation(ctx, req.KeyID, "SIGN", false, err.Error())
		return nil, fmt.Errorf("sign: %w", err)
	}

	k.logOperation(ctx, req.KeyID, "SIGN", true, "")

	return &models.SignResponse{
		KeyID:     key.KeyID,
		Signature: signature,
		Version:   key.Version,
	}, nil
}

// Verify 验证签名
func (k *KMS) Verify(ctx context.Context, req *models.VerifyRequest) (*models.VerifyResponse, error) {
	// 加载密钥
	key, err := k.store.GetKey(ctx, req.KeyID)
	if err != nil {
		k.logOperation(ctx, req.KeyID, "VERIFY", false, err.Error())
		return nil, fmt.Errorf("get key: %w", err)
	}

	// 检查密钥用途
	if key.Usage != models.KeyUsageSignVerify {
		err := fmt.Errorf("key is not for verification: %s", key.Usage)
		k.logOperation(ctx, req.KeyID, "VERIFY", false, err.Error())
		return nil, err
	}

	// 解密私钥（需要从私钥提取公钥）
	// 注意：生产环境应该单独存储公钥以提高性能
	privateKey, err := k.decryptKeyMaterial(key.EncryptedMaterial)
	if err != nil {
		k.logOperation(ctx, req.KeyID, "VERIFY", false, err.Error())
		return nil, fmt.Errorf("decrypt private key: %w", err)
	}
	defer crypto.ClearBytes(privateKey)

	// 这里简化处理，实际应该提取并缓存公钥
	// TODO: 优化公钥提取和缓存

	// 根据算法选择验证方法
	var valid bool
	switch key.Algorithm {
	case models.AlgorithmRSA2048, models.AlgorithmRSA4096:
		valid, err = k.crypto.VerifyRSA(privateKey, req.Message, req.Signature)
	case models.AlgorithmECDSAP256, models.AlgorithmECDSAP384:
		valid, err = k.crypto.VerifyECDSA(privateKey, req.Message, req.Signature)
	default:
		err = fmt.Errorf("unsupported verification algorithm: %s", key.Algorithm)
	}

	if err != nil {
		k.logOperation(ctx, req.KeyID, "VERIFY", false, err.Error())
		return nil, fmt.Errorf("verify: %w", err)
	}

	k.logOperation(ctx, req.KeyID, "VERIFY", true, "")

	return &models.VerifyResponse{
		KeyID:   key.KeyID,
		Valid:   valid,
		Version: key.Version,
	}, nil
}

// RotateKey 轮换密钥（创建新版本）
func (k *KMS) RotateKey(ctx context.Context, keyID string) (*models.RotateKeyResponse, error) {
	// 1. 获取当前密钥
	key, err := k.store.GetKey(ctx, keyID)
	if err != nil {
		k.logOperation(ctx, keyID, "ROTATE_KEY", false, err.Error())
		return nil, fmt.Errorf("get key: %w", err)
	}

	// 2. 检查密钥状态
	if key.State != models.KeyStateEnabled {
		err := fmt.Errorf("cannot rotate key in state: %s", key.State)
		k.logOperation(ctx, keyID, "ROTATE_KEY", false, err.Error())
		return nil, err
	}

	// 3. 获取当前版本
	currentVersion, err := k.store.GetLatestKeyVersion(ctx, key.ID)
	if err != nil {
		k.logOperation(ctx, keyID, "ROTATE_KEY", false, err.Error())
		return nil, fmt.Errorf("get current version: %w", err)
	}

	// 4. 生成新的密钥材料
	var keyMaterial []byte
	switch key.Algorithm {
	case models.AlgorithmAES256GCM:
		keyMaterial, _ = k.crypto.GenerateSymmetricKey(models.AlgorithmAES256GCM) // 256-bit
	case models.AlgorithmRSA2048:
		keyMaterial, _, err = k.crypto.GenerateKeyPair(models.AlgorithmRSA2048)
		if err != nil {
			k.logOperation(ctx, keyID, "ROTATE_KEY", false, err.Error())
			return nil, fmt.Errorf("generate RSA key: %w", err)
		}
	case models.AlgorithmRSA4096:
		keyMaterial, _, err = k.crypto.GenerateKeyPair(models.AlgorithmRSA4096)
		if err != nil {
			k.logOperation(ctx, keyID, "ROTATE_KEY", false, err.Error())
			return nil, fmt.Errorf("generate RSA key: %w", err)
		}
	default:
		err := fmt.Errorf("unsupported algorithm: %s", key.Algorithm)
		k.logOperation(ctx, keyID, "ROTATE_KEY", false, err.Error())
		return nil, err
	}

	// 5. 加密新密钥材料
	encryptedMaterial, err := k.encryptKeyMaterial(keyMaterial)
	if err != nil {
		k.logOperation(ctx, keyID, "ROTATE_KEY", false, err.Error())
		return nil, fmt.Errorf("encrypt key material: %w", err)
	}

	// 6. 创建新版本
	newVersionNumber := currentVersion.VersionNumber + 1
	newVersion := &models.KeyVersion{
		ID:                uuid.New().String(),
		MasterKeyID:       key.ID,
		VersionNumber:     newVersionNumber,
		EncryptedMaterial: encryptedMaterial,
		State:             models.KeyStateEnabled,
		CreatedAt:         time.Now(),
	}

	err = k.store.SaveKeyVersion(ctx, newVersion)
	if err != nil {
		k.logOperation(ctx, keyID, "ROTATE_KEY", false, err.Error())
		return nil, fmt.Errorf("save new version: %w", err)
	}

	// 7. 将旧版本标记为弃用
	if err := k.store.UpdateKeyVersionState(ctx, currentVersion.ID, models.KeyStateDeprecated); err != nil {
		// 记录警告但不失败（新版本已创建）
		k.logger.Warn("failed to deprecate old version",
			zap.String("key_id", keyID),
			zap.Int("old_version", currentVersion.VersionNumber),
			zap.Error(err),
		)
	}

	// 8. 更新主密钥的版本号
	key.Version = newVersionNumber
	key.EncryptedMaterial = encryptedMaterial
	key.UpdatedAt = time.Now()
	if err := k.store.SaveKey(ctx, key); err != nil {
		k.logger.Error("failed to update master key version",
			zap.String("key_id", keyID),
			zap.Error(err),
		)
	}

	k.logOperation(ctx, keyID, "ROTATE_KEY", true, fmt.Sprintf("new_version=%d", newVersionNumber))

	return &models.RotateKeyResponse{
		KeyID:           keyID,
		NewVersion:      newVersionNumber,
		PreviousVersion: currentVersion.VersionNumber,
		RotatedAt:       time.Now(),
	}, nil
}

// GenerateDataKey 生成数据加密密钥（信封加密）
func (k *KMS) GenerateDataKey(ctx context.Context, req *models.GenerateDataKeyRequest) (*models.GenerateDataKeyResponse, error) {
	// 1. 获取 Master Key
	masterKey, err := k.store.GetKey(ctx, req.MasterKeyID)
	if err != nil {
		k.logOperation(ctx, req.MasterKeyID, "GENERATE_DATA_KEY", false, err.Error())
		return nil, fmt.Errorf("get master key: %w", err)
	}

	// 2. 检查密钥状态
	if masterKey.State != models.KeyStateEnabled {
		err := fmt.Errorf("master key not enabled: %s", masterKey.State)
		k.logOperation(ctx, req.MasterKeyID, "GENERATE_DATA_KEY", false, err.Error())
		return nil, err
	}

	// 3. 检查密钥用途
	if masterKey.Usage != models.KeyUsageEncryptDecrypt {
		err := fmt.Errorf("master key usage must be ENCRYPT_DECRYPT, got: %s", masterKey.Usage)
		k.logOperation(ctx, req.MasterKeyID, "GENERATE_DATA_KEY", false, err.Error())
		return nil, err
	}

	// 4. 确定 DEK 大小
	var alg models.KeyAlgorithm
	switch req.KeySpec {
	case "AES_256":
		alg = models.AlgorithmAES256GCM // 256 bits
	case "AES_128":
		alg = models.AlgorithmAES128GCM // 128 bits
	default:
		alg = models.AlgorithmAES256GCM // 默认 256 bits
	}

	// 5. 生成新的 DEK（明文）
	plaintextDEK, err := k.crypto.GenerateSymmetricKey(alg)
	if err != nil {
		return nil, fmt.Errorf("generate symmetric key: %w", err)
	}

	// 6. 获取最新版本的 Master Key 材料
	latestVersion, err := k.store.GetLatestKeyVersion(ctx, masterKey.ID)
	if err != nil {
		k.logOperation(ctx, req.MasterKeyID, "GENERATE_DATA_KEY", false, err.Error())
		return nil, fmt.Errorf("get latest version: %w", err)
	}

	// 7. 解密 Master Key 材料
	masterKeyMaterial, err := k.decryptKeyMaterial(latestVersion.EncryptedMaterial)
	if err != nil {
		k.logOperation(ctx, req.MasterKeyID, "GENERATE_DATA_KEY", false, err.Error())
		return nil, fmt.Errorf("decrypt master key: %w", err)
	}
	defer crypto.ClearBytes(masterKeyMaterial)

	// 8. 用 Master Key 加密 DEK
	ciphertext, iv, tag, err := k.crypto.EncryptAESGCM(masterKeyMaterial, plaintextDEK, nil)
	if err != nil {
		crypto.ClearBytes(plaintextDEK)
		k.logOperation(ctx, req.MasterKeyID, "GENERATE_DATA_KEY", false, err.Error())
		return nil, fmt.Errorf("encrypt DEK: %w", err)
	}

	// 9. 组装加密的 DEK
	// 格式：[Key ID (40 bytes)] + [IV (12 bytes)] + [Tag (16 bytes)] + [Ciphertext]
	encryptedDEK := make([]byte, 0, 40+12+16+len(ciphertext))
	encryptedDEK = append(encryptedDEK, []byte(req.MasterKeyID)...) // 36 bytes
	encryptedDEK = append(encryptedDEK, iv...)                      // 12 bytes
	encryptedDEK = append(encryptedDEK, tag...)                     // 16 bytes
	encryptedDEK = append(encryptedDEK, ciphertext...)              // variable

	k.logOperation(ctx, req.MasterKeyID, "GENERATE_DATA_KEY", true,
		fmt.Sprintf("key_spec=%s,algorithm=%d", req.KeySpec, alg))

	return &models.GenerateDataKeyResponse{
		MasterKeyID:  req.MasterKeyID,
		PlaintextDEK: plaintextDEK, // 客户端应该立即使用后清除
		EncryptedDEK: encryptedDEK, // 存储在数据旁边
		Algorithm:    string(alg),
		KeySpec:      req.KeySpec,
	}, nil
}

// DecryptDataKey 解密数据加密密钥（信封加密）
func (k *KMS) DecryptDataKey(ctx context.Context, req *models.DecryptDataKeyRequest) (*models.DecryptDataKeyResponse, error) {
	// EncryptedDEK 格式：[Key ID (36 bytes)] + [IV (12 bytes)] + [Tag (16 bytes)] + [Ciphertext]
	minSize := 36 + 12 + 16 // Key ID + IV + Tag（至少64字节）
	if len(req.EncryptedDEK) < minSize {
		return nil, fmt.Errorf("invalid encrypted DEK size: got %d, need at least %d", len(req.EncryptedDEK), minSize)
	}

	// 1. 从 EncryptedDEK 中提取 Master Key ID
	masterKeyID := string(req.EncryptedDEK[0:40])

	// 2. 如果请求中指定了 Master Key ID，验证是否匹配
	if req.MasterKeyID != "" && req.MasterKeyID != masterKeyID {
		err := fmt.Errorf("master key ID mismatch: expected %s, got %s", req.MasterKeyID, masterKeyID)
		k.logOperation(ctx, masterKeyID, "DECRYPT_DATA_KEY", false, err.Error())
		return nil, err
	}

	// 3. 提取 IV、Tag 和密文
	iv := req.EncryptedDEK[40:52]       // 12 bytes
	tag := req.EncryptedDEK[52:68]      // 16 bytes
	ciphertext := req.EncryptedDEK[68:] // 剩余部分

	// 4. 获取 Master Key
	masterKey, err := k.store.GetKey(ctx, masterKeyID)
	if err != nil {
		k.logOperation(ctx, masterKeyID, "DECRYPT_DATA_KEY", false, err.Error())
		return nil, fmt.Errorf("get master key: %w", err)
	}

	// 5. 检查密钥状态
	if masterKey.State == models.KeyStateDisabled || masterKey.State == models.KeyStateDeleted {
		err := fmt.Errorf("master key not available: %s", masterKey.State)
		k.logOperation(ctx, masterKeyID, "DECRYPT_DATA_KEY", false, err.Error())
		return nil, err
	}

	// 6. 获取 Master Key 的密钥材料（尝试当前版本）
	latestVersion, err := k.store.GetLatestKeyVersion(ctx, masterKey.ID)
	if err != nil {
		k.logOperation(ctx, masterKeyID, "DECRYPT_DATA_KEY", false, err.Error())
		return nil, fmt.Errorf("get latest version: %w", err)
	}

	// 7. 解密 Master Key 材料
	masterKeyMaterial, err := k.decryptKeyMaterial(latestVersion.EncryptedMaterial)
	if err != nil {
		k.logOperation(ctx, masterKeyID, "DECRYPT_DATA_KEY", false, err.Error())
		return nil, fmt.Errorf("decrypt master key: %w", err)
	}
	defer crypto.ClearBytes(masterKeyMaterial)

	// 8. 用 Master Key 解密 DEK
	plaintextDEK, err := k.crypto.DecryptAESGCM(masterKeyMaterial, ciphertext, iv, tag, nil)
	if err != nil {
		// 如果当前版本解密失败，可能是用旧版本加密的
		// 尝试所有非 DISABLED 的版本
		k.logger.Warn("failed to decrypt with latest version, trying other versions",
			zap.String("key_id", masterKeyID),
			zap.Int("current_version", latestVersion.VersionNumber),
		)

		// TODO: 实现多版本尝试解密
		// 暂时返回错误
		k.logOperation(ctx, masterKeyID, "DECRYPT_DATA_KEY", false, err.Error())
		return nil, fmt.Errorf("decrypt DEK: %w", err)
	}

	k.logOperation(ctx, masterKeyID, "DECRYPT_DATA_KEY", true, "")

	return &models.DecryptDataKeyResponse{
		PlaintextDEK: plaintextDEK,
		MasterKeyID:  masterKeyID,
		Algorithm:    "AES-GCM",
	}, nil
}

// DisableKey 禁用密钥
func (k *KMS) DisableKey(ctx context.Context, keyID string) error {
	err := k.store.UpdateKeyState(ctx, keyID, models.KeyStateDisabled)
	if err != nil {
		k.logOperation(ctx, keyID, "DISABLE_KEY", false, err.Error())
		return err
	}

	k.logOperation(ctx, keyID, "DISABLE_KEY", true, "")
	return nil
}

// EnableKey 启用密钥
func (k *KMS) EnableKey(ctx context.Context, keyID string) error {
	err := k.store.UpdateKeyState(ctx, keyID, models.KeyStateEnabled)
	if err != nil {
		k.logOperation(ctx, keyID, "ENABLE_KEY", false, err.Error())
		return err
	}

	k.logOperation(ctx, keyID, "ENABLE_KEY", true, "")
	return nil
}

// ScheduleKeyDeletion 计划删除密钥
func (k *KMS) ScheduleKeyDeletion(ctx context.Context, keyID string, pendingWindow time.Duration) error {
	// 首先将密钥状态设置为待删除
	err := k.store.UpdateKeyState(ctx, keyID, models.KeyStatePendingDeletion)
	if err != nil {
		k.logOperation(ctx, keyID, "SCHEDULE_DELETION", false, err.Error())
		return err
	}

	// TODO: 实现延迟删除机制（可以使用定时任务或消息队列）
	// 在 pendingWindow 时间后执行实际删除

	k.logOperation(ctx, keyID, "SCHEDULE_DELETION", true, fmt.Sprintf("pending_window=%s", pendingWindow))
	return nil
}

// encryptKeyMaterial 使用 Root Key 加密密钥材料（关键的密钥层级实现）
func (k *KMS) encryptKeyMaterial(keyMaterial []byte) (models.EncryptedKeyMaterial, error) {
	// 使用 Root Key 进行 AES-GCM 加密
	ciphertext, iv, tag, err := k.crypto.EncryptAESGCM(k.rootKey, keyMaterial, nil)
	if err != nil {
		return models.EncryptedKeyMaterial{}, fmt.Errorf("encrypt with root key: %w", err)
	}

	return models.EncryptedKeyMaterial{
		EncryptedData: ciphertext,
		IV:            iv,
		Tag:           tag,
		Algorithm:     "AES-256-GCM",
	}, nil
}

// decryptKeyMaterial 使用 Root Key 解密密钥材料
func (k *KMS) decryptKeyMaterial(encrypted models.EncryptedKeyMaterial) ([]byte, error) {
	// 使用 Root Key 进行 AES-GCM 解密
	plaintext, err := k.crypto.DecryptAESGCM(
		k.rootKey,
		encrypted.EncryptedData,
		encrypted.IV,
		encrypted.Tag,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("decrypt with root key: %w", err)
	}

	return plaintext, nil
}

// generateKeyID 生成密钥 ID
func generateKeyID() string {
	return fmt.Sprintf("key-%s", uuid.New().String())
}

// serializeContext 序列化加密上下文为 AAD
func serializeContext(context map[string]string) ([]byte, error) {
	if len(context) == 0 {
		return nil, nil
	}
	return json.Marshal(context)
}

// logOperation 记录操作日志
func (k *KMS) logOperation(ctx context.Context, keyID, operation string, success bool, errorMsg string) {
	op := &models.KeyOperation{
		KeyID:        keyID,
		Operation:    operation,
		Requestor:    ctxkeys.GetUser(ctx),
		IPAddress:    ctxkeys.GetClientIP(ctx),
		Success:      success,
		ErrorMessage: errorMsg,
		Timestamp:    time.Now(),
	}

	// 日志记录失败不影响主流程
	if err := k.store.LogOperation(ctx, op); err != nil {
		k.logger.Error("failed to write audit log",
			zap.String("key_id", keyID),
			zap.String("operation", operation),
			zap.Error(err))
	}
}
