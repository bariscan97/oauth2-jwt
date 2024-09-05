package mailer 

import (
	"fmt"
	"net/smtp"
	"os"
	"strings"
	"auth_service/models"
	"github.com/labstack/gommon/log"
)

type MailWorker struct {
	From     string
	Password string
	SmtpHost string
	SmtpPort string
	Msg      chan models.Message
}

type IMailWorker interface {
	Templates(msg models.Message) (string, error)
	SendMail(msg models.Message) error
	Worker() 
}

func NewMailWorker(mailer MailWorker) IMailWorker {
	return &mailer
}

func (mailer *MailWorker) Templates(msg models.Message) (string, error) {
	var (
		htmlContent []byte
		err         error
	)
	switch msg.Type {
	case "registerVerify":
		htmlContent, err = os.ReadFile("templates/verify_template.html")
		if err != nil {
			return "" ,fmt.Errorf(err.Error())
		}
	case "forgotPassword":
		htmlContent, err = os.ReadFile("templates/forgotpassword.html")
		if err != nil {
			return "" ,fmt.Errorf(err.Error())
		}
	}
	htmlString := string(htmlContent)

	modifiedHTMLString := strings.Replace(htmlString, "#-token-#", msg.Token, -1)

	return modifiedHTMLString, nil
}

func (mailer *MailWorker) SendMail(msg models.Message) error {
	
	str, _ := mailer.Templates(msg)
	
	subject := "Subject: HTML Email Test\n"
	
	contentType := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	
	auth := smtp.PlainAuth("", mailer.From, mailer.Password, mailer.SmtpHost)

	message := []byte(subject + contentType + str)

	err := smtp.SendMail(mailer.SmtpHost+":"+mailer.SmtpPort, auth, mailer.From, []string{msg.To}, message)
	
	if err != nil {
		return fmt.Errorf(err.Error())
	}

	return nil
}

func (mailer *MailWorker) Worker() {
		
	for msg := range mailer.Msg {
		if err := mailer.SendMail(msg) ; err != nil {
				log.Info(fmt.Println(err.Error()))
				break
			}
			log.Info(fmt.Println("sent successfully"))
		}
	
	}