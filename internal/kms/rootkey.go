package kms

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// GenerateRootKey 生成 Root Key（256-bit AES key）
func GenerateRootKey() ([]byte, error) {
	key := make([]byte, 32) // 256 bits
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate root key: %w", err)
	}
	return key, nil
}

// SaveRootKey 保存 Root Key 到文件
func SaveRootKey(key []byte, path string) error {
	// 获取目录路径
	dir := filepath.Dir(path)

	// 创建目录（如果不存在）
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	// 以 base64 编码保存，便于人工查看
	encoded := base64.StdEncoding.EncodeToString(key)

	// 使用严格的权限（仅所有者可读写）
	if err := os.WriteFile(path, []byte(encoded), 0600); err != nil {
		return fmt.Errorf("save root key: %w", err)
	}

	return nil
}

// LoadRootKey 从文件加载 Root Key
func LoadRootKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read root key file: %w", err)
	}

	// 解码 base64
	key, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("decode root key: %w", err)
	}

	// 验证密钥长度
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid root key length: expected 32 bytes, got %d", len(key))
	}

	return key, nil
}

// InitRootKey 初始化 Root Key（如果不存在则生成）
func InitRootKey(path string) ([]byte, error) {
	// 检查文件是否存在
	if _, err := os.Stat(path); err == nil {
		// 文件存在，加载它
		return LoadRootKey(path)
	}

	// 文件不存在，生成新的 Root Key
	key, err := GenerateRootKey()
	if err != nil {
		return nil, err
	}

	// 保存到文件
	if err := SaveRootKey(key, path); err != nil {
		return nil, err
	}

	return key, nil
}

// SplitRootKey 使用 Shamir 秘密共享分割 Root Key
// 注意：这是简化版本，生产环境应使用成熟的库如 hashicorp/vault/shamir
func SplitRootKey(key []byte, totalShares, threshold int) ([][]byte, error) {
	// TODO: 实现 Shamir 秘密共享算法
	// 这里先返回一个占位实现
	return nil, fmt.Errorf("Shamir secret sharing not implemented yet")
}

// RecoverRootKey 从分片恢复 Root Key
func RecoverRootKey(shares [][]byte) ([]byte, error) {
	// TODO: 实现 Shamir 秘密共享恢复算法
	return nil, fmt.Errorf("Shamir secret recovery not implemented yet")
}
