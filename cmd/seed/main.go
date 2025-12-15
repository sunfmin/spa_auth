package main

import (
	"context"
	"log"
	"os"

	"github.com/user/spa_auth/internal/config"
	"github.com/user/spa_auth/services"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	pb "github.com/user/spa_auth/api/gen/auth/v1"
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

	email := os.Getenv("SUPER_ADMIN_EMAIL")
	password := os.Getenv("SUPER_ADMIN_PASSWORD")

	if email == "" || password == "" {
		log.Fatal("SUPER_ADMIN_EMAIL and SUPER_ADMIN_PASSWORD environment variables are required")
	}

	passwordSvc := services.NewPasswordService(db).Build()
	sessionSvc := services.NewSessionService(db).Build()
	userSvc := services.NewUserService(db).
		WithPasswordService(passwordSvc).
		WithSessionService(sessionSvc).
		Build()
	roleSvc := services.NewRoleService(db).Build()

	ctx := context.Background()

	// Create super_admin role if it doesn't exist
	_, err = roleSvc.GetRole(ctx, &pb.GetRoleRequest{
		Identifier: &pb.GetRoleRequest_Name{Name: "super_admin"},
	})
	if err != nil {
		log.Println("Creating super_admin role...")
		_, err = roleSvc.CreateRole(ctx, &pb.CreateRoleRequest{
			Name:        "super_admin",
			Description: "Super administrator with full access",
		}, "00000000-0000-0000-0000-000000000000")
		if err != nil {
			log.Printf("Warning: Could not create super_admin role: %v", err)
		}
	}

	// Create super admin user
	log.Printf("Creating super admin user: %s", email)
	_, err = userSvc.CreateUser(ctx, &pb.CreateUserRequest{
		Email:    email,
		Password: password,
		Roles:    []string{"super_admin"},
	}, "00000000-0000-0000-0000-000000000000")

	if err != nil {
		log.Printf("Warning: Could not create super admin: %v (user may already exist)", err)
	} else {
		log.Println("Super admin user created successfully")
	}
}
