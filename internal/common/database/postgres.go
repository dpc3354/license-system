package database

import (
	"fmt"
	"time"

	"github.com/dpc3354/license-system/internal/common/config"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq" // PostgreSQL driver
)

// NewPostgresDB 创建 PostgreSQL 数据库连接
func NewPostgresDB(cfg *config.DatabaseConfig) (*sqlx.DB, error) {
	db, err := sqlx.Connect("postgres", cfg.GetDSN())
	if err != nil {
		return nil, fmt.Errorf("connect to database: %w", err)
	}

	// 配置连接池
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	// 测试连接
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return db, nil
}

// MustNewPostgresDB 创建数据库连接，失败则 panic
func MustNewPostgresDB(cfg *config.DatabaseConfig) *sqlx.DB {
	db, err := NewPostgresDB(cfg)
	if err != nil {
		panic(fmt.Sprintf("failed to connect to database: %v", err))
	}
	return db
}

// WaitForDB 等待数据库可用（用于启动时重试）
func WaitForDB(cfg *config.DatabaseConfig, maxRetries int, retryInterval time.Duration) (*sqlx.DB, error) {
	var db *sqlx.DB
	var err error

	for i := 0; i < maxRetries; i++ {
		db, err = NewPostgresDB(cfg)
		if err == nil {
			return db, nil
		}

		if i < maxRetries-1 {
			time.Sleep(retryInterval)
		}
	}

	return nil, fmt.Errorf("failed to connect after %d retries: %w", maxRetries, err)
}
