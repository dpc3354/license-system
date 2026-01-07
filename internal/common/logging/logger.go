package logging

import (
	"os"

	"github.com/dpc3354/license-system/internal/common/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// NewLogger 创建日志实例
func NewLogger(cfg *config.LoggingConfig) (*zap.Logger, error) {
	// 解析日志级别
	level, err := zapcore.ParseLevel(cfg.Level)
	if err != nil {
		level = zapcore.InfoLevel
	}

	// 配置编码器
	var encoderConfig zapcore.EncoderConfig
	if cfg.Format == "json" {
		encoderConfig = zap.NewProductionEncoderConfig()
	} else {
		encoderConfig = zap.NewDevelopmentEncoderConfig()
		encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	// 配置输出
	var output zapcore.WriteSyncer
	switch cfg.OutputPath {
	case "stdout":
		output = zapcore.AddSync(os.Stdout)
	case "stderr":
		output = zapcore.AddSync(os.Stderr)
	default:
		file, err := os.OpenFile(cfg.OutputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		output = zapcore.AddSync(file)
	}

	// 创建 Core
	var encoder zapcore.Encoder
	if cfg.Format == "json" {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	}

	core := zapcore.NewCore(encoder, output, level)

	// 创建 Logger
	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))

	return logger, nil
}

// MustNewLogger 创建日志实例，失败则 panic
func MustNewLogger(cfg *config.LoggingConfig) *zap.Logger {
	logger, err := NewLogger(cfg)
	if err != nil {
		panic(err)
	}
	return logger
}
