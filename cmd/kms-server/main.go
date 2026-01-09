package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	httpapi "github.com/dpc3354/license-system/internal/api/http"
	"github.com/dpc3354/license-system/internal/common/config"
	"github.com/dpc3354/license-system/internal/common/database"
	"github.com/dpc3354/license-system/internal/common/logging"
	"github.com/dpc3354/license-system/internal/kms"
	"github.com/dpc3354/license-system/internal/kms/crypto"
	"github.com/dpc3354/license-system/internal/kms/keystore"
)

var (
	configPath = flag.String("config", "config.yaml", "配置文件路径")
	initRoot   = flag.Bool("init-root", false, "初始化 Root Key")
)

func main() {
	flag.Parse()

	// 加载配置
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		// 配置文件不存在时使用默认配置
		fmt.Printf("加载配置失败，使用默认配置: %v\n", err)
		cfg = config.DefaultConfig()
	}

	// 初始化日志
	logger := logging.MustNewLogger(&cfg.Logging)
	defer logger.Sync()

	logger.Info("启动 KMS 服务器",
		zap.String("version", "1.0.0"),
		zap.String("config", *configPath),
	)

	// 初始化或加载 Root Key
	rootKey, err := kms.InitRootKey(cfg.KMS.RootKeyPath)
	if err != nil {
		logger.Fatal("初始化 Root Key 失败", zap.Error(err))
	}
	logger.Info("Root Key 已加载", zap.String("path", cfg.KMS.RootKeyPath))

	// 如果只是初始化 Root Key，则退出
	if *initRoot {
		logger.Info("Root Key 初始化完成，程序退出")
		return
	}

	// 连接数据库（带重试）
	logger.Info("连接数据库...",
		zap.String("host", cfg.Database.Host),
		zap.Int("port", cfg.Database.Port),
	)

	db, err := database.WaitForDB(&cfg.Database, 10, 5*time.Second)
	if err != nil {
		logger.Fatal("连接数据库失败", zap.Error(err))
	}
	defer db.Close()
	logger.Info("数据库连接成功")

	// 初始化 KMS 组件
	cryptoEngine := crypto.NewStandardCryptoEngine()
	store := keystore.NewPostgreSQLKeyStore(db)
	kmsCore := kms.NewKMS(cryptoEngine, store, rootKey, logger)

	logger.Info("KMS 核心组件初始化完成")

	// 创建 HTTP 路由
	router := httpapi.NewRouter(kmsCore, logger)
	mux := router.Setup()

	// 应用中间件
	var handler http.Handler = mux
	handler = httpapi.RecoveryMiddleware(logger)(handler)
	handler = httpapi.LoggingMiddleware(logger)(handler)
	handler = httpapi.ClientIPMiddleware()(handler)
	handler = httpapi.CORSMiddleware()(handler)

	// 创建 HTTP 服务器
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	server := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	// 启动服务器
	go func() {
		addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
		logger.Info("启动 HTTP 服务器", zap.String("addr", addr))

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("HTTP 服务器启动失败", zap.Error(err))
		}
	}()

	// 优雅关闭
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("正在关闭服务器...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("服务器关闭失败", zap.Error(err))
	}

	logger.Info("服务器已关闭")
}
