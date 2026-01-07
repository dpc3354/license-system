package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config 应用配置
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	KMS      KMSConfig      `yaml:"kms"`
	Logging  LoggingConfig  `yaml:"logging"`
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Host         string        `yaml:"host"`
	Port         int           `yaml:"port"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
}

// DatabaseConfig 数据库配置
type DatabaseConfig struct {
	Host            string        `yaml:"host"`
	Port            int           `yaml:"port"`
	User            string        `yaml:"user"`
	Password        string        `yaml:"password"`
	DBName          string        `yaml:"dbname"`
	SSLMode         string        `yaml:"sslmode"`
	MaxOpenConns    int           `yaml:"max_open_conns"`
	MaxIdleConns    int           `yaml:"max_idle_conns"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime"`
}

// KMSConfig KMS 特定配置
type KMSConfig struct {
	RootKeyPath string `yaml:"root_key_path"` // Root Key 文件路径
	HSMEnabled  bool   `yaml:"hsm_enabled"`   // 是否启用 HSM
	HSMConfig   string `yaml:"hsm_config"`    // HSM 配置
}

// LoggingConfig 日志配置
type LoggingConfig struct {
	Level      string `yaml:"level"`       // debug, info, warn, error
	Format     string `yaml:"format"`      // json, console
	OutputPath string `yaml:"output_path"` // stdout, stderr, or file path
}

// LoadConfig 从文件加载配置
func LoadConfig(configPath string) (*Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}

	// 从环境变量覆盖敏感配置
	if dbPassword := os.Getenv("DB_PASSWORD"); dbPassword != "" {
		config.Database.Password = dbPassword
	}

	if rootKeyPath := os.Getenv("ROOT_KEY_PATH"); rootKeyPath != "" {
		config.KMS.RootKeyPath = rootKeyPath
	}

	return &config, nil
}

// GetDSN 获取数据库连接字符串
func (c *DatabaseConfig) GetDSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.DBName, c.SSLMode,
	)
}

// DefaultConfig 返回默认配置
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:         "0.0.0.0",
			Port:         50051,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		},
		Database: DatabaseConfig{
			Host:            "localhost",
			Port:            5432,
			User:            "kms",
			Password:        "kms_password",
			DBName:          "kms",
			SSLMode:         "disable",
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: 5 * time.Minute,
		},
		KMS: KMSConfig{
			RootKeyPath: "/keys/root.key",
			HSMEnabled:  false,
		},
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "json",
			OutputPath: "stdout",
		},
	}
}
