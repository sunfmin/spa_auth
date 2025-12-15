package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/user/spa_auth/handlers"
	"github.com/user/spa_auth/internal/config"
	"github.com/user/spa_auth/services"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	cfg := config.Load()

	db, err := gorm.Open(postgres.Open(cfg.DatabaseURL), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	if err := services.AutoMigrate(db); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	passwordSvc := services.NewPasswordService(db).Build()
	jwtSvc := services.NewJWTService(cfg.JWTSecret).
		WithAccessTTL(cfg.JWTAccessTTL).
		WithRefreshTTL(cfg.JWTRefreshTTL).
		Build()
	sessionSvc := services.NewSessionService(db).Build()

	authSvc := services.NewAuthService(db).
		WithPasswordService(passwordSvc).
		WithJWTService(jwtSvc).
		WithSessionService(sessionSvc).
		Build()

	userSvc := services.NewUserService(db).
		WithPasswordService(passwordSvc).
		WithSessionService(sessionSvc).
		Build()

	roleSvc := services.NewRoleService(db).Build()

	mux := handlers.NewRouter().
		WithAuthService(authSvc).
		WithUserService(userSvc).
		WithRoleService(roleSvc).
		WithMiddlewares(handlers.DefaultMiddlewares()...).
		Build()

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("Starting server on port %s", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited gracefully")
}
