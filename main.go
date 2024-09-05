package main

import (
	"auth_service/controller"
	"auth_service/database"
	"auth_service/mailer"
	"auth_service/models"
	"os"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)



func main() {

	godotenv.Load()
	e := echo.New()
	
	e.Use(middleware.CORS())
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	db := database.ConnectDatabase()

	m := mailer.MailWorker{
		From:     os.Getenv("SMTP_PUBLISHER"),
		Password: os.Getenv("SMTP_PASSWORD"),
		SmtpHost: os.Getenv("SMTP_HOST"),
		SmtpPort: os.Getenv("SMTP_PORT"),
		Msg:      make(chan models.Message, 10),
	}

	routes := controller.NewAuthController(db, m.Msg)

	routes.RegisterRoutes(e)

	go m.Worker()

	e.Start(":8080")
}
