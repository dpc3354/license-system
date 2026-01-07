package crypto

import (
	"testing"

	"github.com/dpc3354/license-system/internal/kms/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStandardCryptoEngine_GenerateSymmetricKey(t *testing.T) {
	engine := NewStandardCryptoEngine()

	testCases := []struct {
		name      string
		algorithm models.KeyAlgorithm
		keySize   int
	}{
		{
			name:      "AES-256",
			algorithm: models.AlgorithmAES256GCM,
			keySize:   32,
		},
		{
			name:      "AES-128",
			algorithm: models.AlgorithmAES128GCM,
			keySize:   16,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := engine.GenerateSymmetricKey(tc.algorithm)
			require.NoError(t, err)
			assert.Equal(t, tc.keySize, len(key))

			// 生成的密钥应该是随机的
			key2, err := engine.GenerateSymmetricKey(tc.algorithm)
			require.NoError(t, err)
			assert.NotEqual(t, key, key2, "生成的密钥应该不同")
		})
	}
}

func TestStandardCryptoEngine_EncryptDecrypt(t *testing.T) {
	engine := NewStandardCryptoEngine()

	// 生成密钥
	key, err := engine.GenerateSymmetricKey(models.AlgorithmAES256GCM)
	require.NoError(t, err)

	testCases := []struct {
		name           string
		plaintext      []byte
		additionalData []byte
	}{
		{
			name:           "简单文本",
			plaintext:      []byte("Hello, World!"),
			additionalData: nil,
		},
		{
			name:           "带 AAD 的加密",
			plaintext:      []byte("Sensitive data"),
			additionalData: []byte("context-info"),
		},
		{
			name:           "空数据",
			plaintext:      []byte{},
			additionalData: nil,
		},
		{
			name:           "二进制数据",
			plaintext:      []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE},
			additionalData: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 加密
			ciphertext, iv, tag, err := engine.EncryptAESGCM(key, tc.plaintext, tc.additionalData)
			require.NoError(t, err)
			assert.NotEqual(t, tc.plaintext, ciphertext, "密文不应该等于明文")
			assert.Equal(t, 12, len(iv), "IV 长度应该是 12 字节")
			assert.Equal(t, 16, len(tag), "Tag 长度应该是 16 字节")

			// 解密
			decrypted, err := engine.DecryptAESGCM(key, ciphertext, iv, tag, tc.additionalData)
			require.NoError(t, err)
			assert.Equal(t, tc.plaintext, decrypted, "解密后应该得到原始明文")
		})
	}
}

func TestStandardCryptoEngine_EncryptDecrypt_WrongKey(t *testing.T) {
	engine := NewStandardCryptoEngine()

	key1, err := engine.GenerateSymmetricKey(models.AlgorithmAES256GCM)
	require.NoError(t, err)

	key2, err := engine.GenerateSymmetricKey(models.AlgorithmAES256GCM)
	require.NoError(t, err)

	plaintext := []byte("Secret message")

	// 使用 key1 加密
	ciphertext, iv, tag, err := engine.EncryptAESGCM(key1, plaintext, nil)
	require.NoError(t, err)

	// 使用 key2 解密应该失败
	_, err = engine.DecryptAESGCM(key2, ciphertext, iv, tag, nil)
	assert.Error(t, err, "使用错误的密钥解密应该失败")
}

func TestStandardCryptoEngine_EncryptDecrypt_WrongAAD(t *testing.T) {
	engine := NewStandardCryptoEngine()

	key, err := engine.GenerateSymmetricKey(models.AlgorithmAES256GCM)
	require.NoError(t, err)

	plaintext := []byte("Secret message")
	aad1 := []byte("context-1")
	aad2 := []byte("context-2")

	// 使用 aad1 加密
	ciphertext, iv, tag, err := engine.EncryptAESGCM(key, plaintext, aad1)
	require.NoError(t, err)

	// 使用 aad2 解密应该失败（AAD 不匹配）
	_, err = engine.DecryptAESGCM(key, ciphertext, iv, tag, aad2)
	assert.Error(t, err, "AAD 不匹配时解密应该失败")

	// 使用正确的 AAD 应该成功
	decrypted, err := engine.DecryptAESGCM(key, ciphertext, iv, tag, aad1)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestStandardCryptoEngine_GenerateKeyPair_RSA(t *testing.T) {
	engine := NewStandardCryptoEngine()

	testCases := []struct {
		name      string
		algorithm models.KeyAlgorithm
	}{
		{
			name:      "RSA-2048",
			algorithm: models.AlgorithmRSA2048,
		},
		{
			name:      "RSA-4096",
			algorithm: models.AlgorithmRSA4096,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			privateKey, publicKey, err := engine.GenerateKeyPair(tc.algorithm)
			require.NoError(t, err)
			assert.NotEmpty(t, privateKey)
			assert.NotEmpty(t, publicKey)

			// 私钥应该包含 PEM 头
			assert.Contains(t, string(privateKey), "BEGIN RSA PRIVATE KEY")
			assert.Contains(t, string(publicKey), "BEGIN PUBLIC KEY")
		})
	}
}

func TestStandardCryptoEngine_SignVerify_RSA(t *testing.T) {
	engine := NewStandardCryptoEngine()

	// 生成密钥对
	privateKey, publicKey, err := engine.GenerateKeyPair(models.AlgorithmRSA2048)
	require.NoError(t, err)

	message := []byte("This is a message to be signed")

	// 签名
	signature, err := engine.SignRSA(privateKey, message)
	require.NoError(t, err)
	assert.NotEmpty(t, signature)

	// 验证签名
	valid, err := engine.VerifyRSA(publicKey, message, signature)
	require.NoError(t, err)
	assert.True(t, valid, "签名应该有效")

	// 验证错误的消息
	wrongMessage := []byte("Different message")
	valid, err = engine.VerifyRSA(publicKey, wrongMessage, signature)
	require.NoError(t, err)
	assert.False(t, valid, "错误消息的签名应该无效")
}

func TestStandardCryptoEngine_GenerateKeyPair_ECDSA(t *testing.T) {
	engine := NewStandardCryptoEngine()

	testCases := []struct {
		name      string
		algorithm models.KeyAlgorithm
	}{
		{
			name:      "ECDSA-P256",
			algorithm: models.AlgorithmECDSAP256,
		},
		{
			name:      "ECDSA-P384",
			algorithm: models.AlgorithmECDSAP384,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			privateKey, publicKey, err := engine.GenerateKeyPair(tc.algorithm)
			require.NoError(t, err)
			assert.NotEmpty(t, privateKey)
			assert.NotEmpty(t, publicKey)

			// 私钥应该包含 PEM 头
			assert.Contains(t, string(privateKey), "BEGIN EC PRIVATE KEY")
			assert.Contains(t, string(publicKey), "BEGIN PUBLIC KEY")
		})
	}
}

func TestStandardCryptoEngine_SignVerify_ECDSA(t *testing.T) {
	engine := NewStandardCryptoEngine()

	// 生成密钥对
	privateKey, publicKey, err := engine.GenerateKeyPair(models.AlgorithmECDSAP256)
	require.NoError(t, err)

	message := []byte("This is a message to be signed")

	// 签名
	signature, err := engine.SignECDSA(privateKey, message)
	require.NoError(t, err)
	assert.NotEmpty(t, signature)

	// 验证签名
	valid, err := engine.VerifyECDSA(publicKey, message, signature)
	require.NoError(t, err)
	assert.True(t, valid, "签名应该有效")

	// 验证错误的消息
	wrongMessage := []byte("Different message")
	valid, err = engine.VerifyECDSA(publicKey, wrongMessage, signature)
	require.NoError(t, err)
	assert.False(t, valid, "错误消息的签名应该无效")
}

func TestClearBytes(t *testing.T) {
	data := []byte("sensitive data")
	original := make([]byte, len(data))
	copy(original, data)

	ClearBytes(data)

	// 验证所有字节都被清零
	for i, b := range data {
		assert.Equal(t, byte(0), b, "字节 %d 应该被清零", i)
	}

	// 验证原始数据不同
	assert.NotEqual(t, original, data)
}

func BenchmarkAESGCMEncrypt(b *testing.B) {
	engine := NewStandardCryptoEngine()
	key, _ := engine.GenerateSymmetricKey(models.AlgorithmAES256GCM)
	plaintext := make([]byte, 1024) // 1KB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = engine.EncryptAESGCM(key, plaintext, nil)
	}
}

func BenchmarkRSASign(b *testing.B) {
	engine := NewStandardCryptoEngine()
	privateKey, _, _ := engine.GenerateKeyPair(models.AlgorithmRSA2048)
	message := []byte("benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = engine.SignRSA(privateKey, message)
	}
}

func BenchmarkECDSASign(b *testing.B) {
	engine := NewStandardCryptoEngine()
	privateKey, _, _ := engine.GenerateKeyPair(models.AlgorithmECDSAP256)
	message := []byte("benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = engine.SignECDSA(privateKey, message)
	}
}
