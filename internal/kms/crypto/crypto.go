package crypto

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/dpc3354/license-system/internal/kms/models"
)

// CryptoEngine 加密引擎接口
type CryptoEngine interface {
	// GenerateKeyPair 生成非对称密钥对
	GenerateKeyPair(algo models.KeyAlgorithm) (privateKey, publicKey []byte, err error)

	// GenerateSymmetricKey 生成对称密钥
	GenerateSymmetricKey(algo models.KeyAlgorithm) ([]byte, error)

	// EncryptAESGCM 使用 AES-GCM 加密
	EncryptAESGCM(key, plaintext, additionalData []byte) (ciphertext, iv, tag []byte, err error)

	// DecryptAESGCM 使用 AES-GCM 解密
	DecryptAESGCM(key, ciphertext, iv, tag, additionalData []byte) ([]byte, error)

	// SignRSA 使用 RSA 私钥签名
	SignRSA(privateKey, message []byte) ([]byte, error)

	// VerifyRSA 使用 RSA 公钥验证签名
	VerifyRSA(publicKey, message, signature []byte) (bool, error)

	// SignECDSA 使用 ECDSA 私钥签名
	SignECDSA(privateKey, message []byte) ([]byte, error)

	// VerifyECDSA 使用 ECDSA 公钥验证签名
	VerifyECDSA(publicKey, message, signature []byte) (bool, error)
}

// StandardCryptoEngine 标准加密引擎实现（基于 Go 标准库）
type StandardCryptoEngine struct{}

// NewStandardCryptoEngine 创建标准加密引擎
func NewStandardCryptoEngine() *StandardCryptoEngine {
	return &StandardCryptoEngine{}
}

// GenerateKeyPair 生成非对称密钥对
func (e *StandardCryptoEngine) GenerateKeyPair(algo models.KeyAlgorithm) ([]byte, []byte, error) {
	switch algo {
	case models.AlgorithmRSA2048:
		return e.generateRSAKeyPair(2048)
	case models.AlgorithmRSA4096:
		return e.generateRSAKeyPair(4096)
	case models.AlgorithmECDSAP256:
		return e.generateECDSAKeyPair(elliptic.P256())
	case models.AlgorithmECDSAP384:
		return e.generateECDSAKeyPair(elliptic.P384())
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm for key pair: %s", algo)
	}
}

// generateRSAKeyPair 生成 RSA 密钥对
func (e *StandardCryptoEngine) generateRSAKeyPair(bits int) ([]byte, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("generate RSA key: %w", err)
	}

	// 编码私钥
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// 编码公钥
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal public key: %w", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return privateKeyPEM, publicKeyPEM, nil
}

// generateECDSAKeyPair 生成 ECDSA 密钥对
func (e *StandardCryptoEngine) generateECDSAKeyPair(curve elliptic.Curve) ([]byte, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ECDSA key: %w", err)
	}

	// 编码私钥
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal EC private key: %w", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// 编码公钥
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal public key: %w", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return privateKeyPEM, publicKeyPEM, nil
}

// GenerateSymmetricKey 生成对称密钥
func (e *StandardCryptoEngine) GenerateSymmetricKey(algo models.KeyAlgorithm) ([]byte, error) {
	var keySize int

	switch algo {
	case models.AlgorithmAES256GCM:
		keySize = 32 // 256 bits
	case models.AlgorithmAES128GCM:
		keySize = 16 // 128 bits
	default:
		return nil, fmt.Errorf("unsupported symmetric algorithm: %s", algo)
	}

	key := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate symmetric key: %w", err)
	}

	return key, nil
}

// EncryptAESGCM 使用 AES-GCM 加密
func (e *StandardCryptoEngine) EncryptAESGCM(key, plaintext, additionalData []byte) ([]byte, []byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create GCM: %w", err)
	}

	// 生成随机 nonce (IV)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("generate nonce: %w", err)
	}

	// 加密并获取密文 + tag
	// Seal 返回: nonce || ciphertext || tag 的形式，但我们需要分开存储
	sealed := gcm.Seal(nil, nonce, plaintext, additionalData)

	// GCM tag 长度默认是 16 bytes
	tagSize := 16
	ciphertext := sealed[:len(sealed)-tagSize]
	tag := sealed[len(sealed)-tagSize:]

	return ciphertext, nonce, tag, nil
}

// DecryptAESGCM 使用 AES-GCM 解密
func (e *StandardCryptoEngine) DecryptAESGCM(key, ciphertext, iv, tag, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	// 组合 ciphertext + tag
	sealed := append(ciphertext, tag...)

	// 解密
	plaintext, err := gcm.Open(nil, iv, sealed, additionalData)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

// SignRSA 使用 RSA 私钥签名
func (e *StandardCryptoEngine) SignRSA(privateKeyPEM, message []byte) ([]byte, error) {
	// 解析私钥
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	// 计算消息哈希
	hashed := sha256.Sum256(message)

	// 签名
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	return signature, nil
}

// VerifyRSA 使用 RSA 公钥验证签名
func (e *StandardCryptoEngine) VerifyRSA(publicKeyPEM, message, signature []byte) (bool, error) {
	// 解析公钥
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return false, fmt.Errorf("failed to decode PEM block")
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("parse public key: %w", err)
	}

	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("not an RSA public key")
	}

	// 计算消息哈希
	hashed := sha256.Sum256(message)

	// 验证签名
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
	return err == nil, nil
}

// SignECDSA 使用 ECDSA 私钥签名
func (e *StandardCryptoEngine) SignECDSA(privateKeyPEM, message []byte) ([]byte, error) {
	// 解析私钥
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse EC private key: %w", err)
	}

	// 计算消息哈希
	hashed := sha256.Sum256(message)

	// 签名（返回 r, s 值的 ASN.1 编码）
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hashed[:])
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	return signature, nil
}

// VerifyECDSA 使用 ECDSA 公钥验证签名
func (e *StandardCryptoEngine) VerifyECDSA(publicKeyPEM, message, signature []byte) (bool, error) {
	// 解析公钥
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return false, fmt.Errorf("failed to decode PEM block")
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("parse public key: %w", err)
	}

	publicKey, ok := publicKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("not an ECDSA public key")
	}

	// 计算消息哈希
	hashed := sha256.Sum256(message)

	// 验证签名
	valid := ecdsa.VerifyASN1(publicKey, hashed[:], signature)
	return valid, nil
}

// ClearBytes 安全清除字节数组（防止密钥残留在内存中）
func ClearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
