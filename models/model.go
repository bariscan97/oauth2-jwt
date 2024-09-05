package models

import (
	"time"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

type User struct {
	ID                  uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primary_key"`
	Username            string    `gorm:"type:varchar(50);uniqueIndex;not null"`
	Email               string    `gorm:"type:varchar(100);uniqueIndex;not null"`
	Password            string    `gorm:"type:text;default:NULL"`
	ResetToken          string    `gorm:"type:text;default:NULL"`
	ResetTokenExpiry    int64     `gorm:"default:NULL"`
	OAuthProvider       string    `gorm:"type:varchar(50);default:NULL"`
	OAuthID             string    `gorm:"type:varchar(100);default:NULL"`
	IsVerified          bool      `gorm:"default:false"`
	VerificationToken   string    `gorm:"size:64"`
	IsOAuthUser         bool      `gorm:"default:false"`
	ResetPasswordToken  string    `gorm:"type:text;default:NULL"`
	ResetPasswordExpire time.Time `gorm:"default:NULL"`
	CreatedAt           time.Time `gorm:"autoCreateTime"`
}

type UserOauth struct {
	Username      string
	Email         string
	OAuthProvider string
	OAuthID       string
	IsOAuthUser   bool
}

type RegisterRequest struct {
	Username string `json:"username" validate:"required,min=8,max=24"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8,max=24"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8,max=24"`
}

type ForgotPassword struct {
	Email string `json:"email" validate:"required,email"`
}

type ResetPassword struct {
	Password string `json:"password" validate:"required,min=8,max=24"`
}

type MyCustomClaims struct {
	Username string
	Email    string
	jwt.StandardClaims
}

type MailWorker struct {
	From     string
	Password string
	SmtpHost string
	SmtpPort string
	Msg      chan Message
}

type Message struct {
	Type  string
	Token string
	To    string
}

