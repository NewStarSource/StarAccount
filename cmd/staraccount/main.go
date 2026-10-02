package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"staraccount/internal/account"
)

func main() {
	logger := log.New(os.Stdout, "staraccount ", log.LstdFlags|log.LUTC)
	if len(os.Args) > 1 && os.Args[1] == "init-dev" {
		if err := account.InitDevelopment(); err != nil {
			logger.Fatal("初始化失败：", err)
		}
		logger.Print("本机合成配置已创建于 .local/development.json")
		return
	}
	filename := flag.String("config", ".local/development.json", "配置文件路径")
	flag.Parse()
	config, keys, err := account.LoadConfig(*filename)
	if err != nil {
		logger.Fatal(err)
	}
	app, err := account.New(config, keys, logger)
	if err != nil {
		logger.Fatal("启动失败：数据库、迁移或密钥不可用")
	}
	defer app.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	var worker sync.WaitGroup
	worker.Add(1)
	go func() { defer worker.Done(); app.Worker(ctx) }()
	server := &http.Server{Addr: config.Address, Handler: app.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	stopped := make(chan struct{})
	go func() {
		<-ctx.Done()
		shutdown, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		_ = server.Shutdown(shutdown)
		close(stopped)
	}()
	logger.Print("本机内部测试服务启动：", config.Origin, "；真实服务未联调")
	if err = server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Print("监听失败")
	}
	cancel()
	<-stopped
	worker.Wait()
}
