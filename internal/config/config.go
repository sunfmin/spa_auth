package config

import (
	"os"
	"time"
)

type Config struct {
	DatabaseURL string

	JWTSecret       string
	JWTAccessTTL    time.Duration
	JWTRefreshTTL   time.Duration

	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURL  string

	SuperAdminEmail    string
	SuperAdminPassword string

	AWSRegion    string
	SESFromEmail string

	RateLimitEnabled bool
	RateLimitStore   string
	RedisURL         string

	HideErrorDetails bool
}

func Load() *Config {
	return &Config{
		DatabaseURL: getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/spa_auth?sslmode=disable"),

		JWTSecret:     getEnv("AUTH_JWT_SECRET", "default-secret-change-in-production"),
		JWTAccessTTL:  parseDuration(getEnv("AUTH_JWT_ACCESS_TTL", "15m")),
		JWTRefreshTTL: parseDuration(getEnv("AUTH_JWT_REFRESH_TTL", "168h")),

		GoogleClientID:     getEnv("GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret: getEnv("GOOGLE_CLIENT_SECRET", ""),
		GoogleRedirectURL:  getEnv("GOOGLE_REDIRECT_URL", "http://localhost:8080/api/v1/oauth/google/callback"),

		SuperAdminEmail:    getEnv("SUPER_ADMIN_EMAIL", "admin@example.com"),
		SuperAdminPassword: getEnv("SUPER_ADMIN_PASSWORD", ""),

		AWSRegion:    getEnv("AWS_REGION", "us-east-1"),
		SESFromEmail: getEnv("SES_FROM_EMAIL", "noreply@example.com"),

		RateLimitEnabled: getEnv("RATE_LIMIT_ENABLED", "true") == "true",
		RateLimitStore:   getEnv("RATE_LIMIT_STORE", "memory"),
		RedisURL:         getEnv("REDIS_URL", ""),

		HideErrorDetails: getEnv("HIDE_ERROR_DETAILS", "false") == "true",
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 15 * time.Minute
	}
	return d
}
