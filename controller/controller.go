package controller

import (
	"auth_service/models"
	"auth_service/utils"
	"auth_service/utils/googleoauth"
	"net/http"
	"os"
	"time"
    "github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)



type AuthController struct {
	Db      *gorm.DB
	Message chan models.Message
}

func NewAuthController(db *gorm.DB, message chan models.Message) *AuthController {
	return &AuthController{
		Db:      db,
		Message: message,
	}
}

func (controller *AuthController) RegisterRoutes(e *echo.Echo) {
	e.POST("/api/auth/register", controller.Register)
	e.POST("/api/auth/login", controller.Login)
	e.POST("/api/auth/forgotpassword", controller.ForgotPassword)
	e.GET("/api/auth/verify", controller.Verify)
	e.POST("/api/auth/resetpassword", controller.ResetPassword)
	e.GET("/api/auth/google_callback", controller.HandleGoogleCallback)
}

func (controller *AuthController) HandleGoogleCallback(c echo.Context) error {
	content, err := googleoauth.GetUserInfo(c.QueryParam("state"), c.QueryParam("code"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": err.Error(),
		})
	}

	user := models.User{
		Username: content["name"].(string),
		Email:    content["email"].(string),
	}

	if err := controller.Db.First(&user, "email = ?", user.Email); err.Error != nil {
		if err := controller.Db.Create(&user); err.Error != nil {
			return c.JSON(http.StatusBadRequest, echo.Map{
				"error": err.Error.Error(),
			})
		}
	}

	SecretKey := os.Getenv("JWT_SECRET")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
		"email":    user.Email,
	})

	tokenString, err := token.SignedString([]byte(SecretKey))

	if err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": err.Error(),
		})
	}

	cookie := new(http.Cookie)
	cookie.Name = "acces_token"
	cookie.Value = tokenString
	cookie.HttpOnly = true
	cookie.Secure = false
	cookie.Path = "/"
	cookie.Expires = time.Now().Add(72 * time.Hour)

	c.SetCookie(cookie)

	return c.JSON(http.StatusBadRequest, echo.Map{
		"username":    user.Username,
		"email":       user.Email,
		"acces_token": tokenString,
	})
}

func (controller *AuthController) Register(c echo.Context) error {
	var reqbody models.RegisterRequest

	if err := c.Bind(&reqbody); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": err.Error(),
		})
	}

	validate := validator.New()

	if err := validate.Struct(reqbody); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": err.Error(),
		})
	}
	user := models.User{
		Username: reqbody.Username,
		Email:    reqbody.Email,
		Password: reqbody.Password,
	}

	bytePassword := []byte(user.Password)

	hash, err := bcrypt.GenerateFromPassword(bytePassword, bcrypt.DefaultCost)

	if err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": err.Error(),
		})
	}

	user.Password = string(hash)

	if err := controller.Db.Create(&user); err.Error != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": err.Error.Error(),
		})
	}
	token := utils.GenerateSecureToken()

	user.VerificationToken = token

	if err := controller.Db.Save(&user); err.Error != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": err.Error.Error(),
		})
	}

	controller.Message <- models.Message{ // chan <-----
		Type:  "registerVerify",
		Token: user.VerificationToken,
		To:    reqbody.Email,
	}

	return c.JSON(http.StatusBadRequest, echo.Map{
		"message": "mail sent to confirm account",
	})
}

func (controller *AuthController) Verify(c echo.Context) error {
	token := c.QueryParam("token")

	var user models.User

	if err := controller.Db.First(&user, "verification_token = ?", token); err.Error != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": err.Error.Error(),
		})
	}

	if user.IsVerified {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": "user already verified",
		})
	}

	user.IsVerified = true

	if err := controller.Db.Save(&user); err.Error != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": err.Error.Error(),
		})
	}

	return c.JSON(http.StatusBadRequest, echo.Map{
		"message": "register succesful",
		"user":    user,
	})
}

func (controller *AuthController) Login(c echo.Context) error {
	var reqbody models.LoginRequest

	if err := c.Bind(&reqbody); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": err.Error(),
		})
	}

	validate := validator.New()

	if err := validate.Struct(reqbody); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": err.Error(),
		})
	}
	user := models.User{
		Email:    reqbody.Email,
		Password: reqbody.Password,
	}

	if err := controller.Db.First(&user, "email = ?", user.Email); err.Error != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": err.Error.Error(),
		})
	}

	if !user.IsVerified {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": "user not verified",
		})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(reqbody.Password)); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": err.Error(),
		})
	}

	SecretKey := os.Getenv("JWT_SECRET")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
		"email":    user.Email,
	})

	tokenString, err := token.SignedString([]byte(SecretKey))

	if err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": err.Error(),
		})
	}

	cookie := new(http.Cookie)
	cookie.Name = "acces_token"
	cookie.Value = tokenString
	cookie.HttpOnly = true
	cookie.Secure = false
	cookie.Path = "/"
	cookie.Expires = time.Now().Add(72 * time.Hour)

	c.SetCookie(cookie)

	return c.JSON(http.StatusBadRequest, echo.Map{
		"username":    user.Username,
		"email":       user.Email,
		"acces_token": tokenString,
	})
}

func (controller *AuthController) ForgotPassword(c echo.Context) error {

	var reqbody models.ForgotPassword

	if err := c.Bind(&reqbody); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": err.Error(),
		})
	}

	validate := validator.New()

	if err := validate.Struct(reqbody); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": err.Error(),
		})
	}

	user := models.User{
		Email: reqbody.Email,
	}

	if err := controller.Db.First(&user, "email = ?", user.Email); err.Error != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": err.Error.Error(),
		})
	}

	if !user.IsVerified {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": "user not verified",
		})
	}

	user.ResetPasswordToken = utils.GenerateSecureToken()

	user.ResetPasswordExpire = time.Now().Add(72 * time.Hour)

	if err := controller.Db.Save(&user); err.Error != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": err.Error.Error(),
		})
	}

	controller.Message <- models.Message{ // chan <-----
		Type:  "forgotPassword",
		Token: user.ResetPasswordToken,
		To:    reqbody.Email,
	}

	return c.JSON(http.StatusBadRequest, echo.Map{
		"message": "mail sent to resetpassword template",
	})

}

func (controller *AuthController) ResetPassword(c echo.Context) error {

	token := c.QueryParam("token")

	var (
		user     models.User
		password models.ResetPassword
	)

	if err := c.Bind(&password); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": err.Error(),
		})
	}

	validate := validator.New()

	if err := validate.Struct(password); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": err.Error(),
		})
	}

	if err := controller.Db.First(&user, "reset_password_token = ?", token); err.Error != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": err.Error.Error(),
		})
	}

	if user.ResetPasswordExpire.Before(time.Now()) {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": "token has expired",
		})
	}

	bytePassword := []byte(user.Password)

	hash, err := bcrypt.GenerateFromPassword(bytePassword, bcrypt.DefaultCost)

	if err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": err.Error(),
		})
	}

	user.Password = string(hash)
	user.ResetPasswordExpire = time.Now().Add(-time.Hour)
	user.ResetPasswordToken = ""

	if err := controller.Db.Save(&user); err.Error != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": err.Error.Error(),
		})
	}

	return c.JSON(http.StatusBadRequest, echo.Map{
		"message": "resetpassword succesful",
	})

}
