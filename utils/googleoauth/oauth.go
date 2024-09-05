package googleoauth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"encoding/json"
	"os"
)

var (
	googleOauthConfig *oauth2.Config
	oauthStateString = "pseudo-random"
)

func init() {
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}
}

func GetUserInfo(state string, code string) (map[string]interface{}, error) {
	
	if state != oauthStateString {
		return nil, fmt.Errorf("invalid oauth state")
	}

	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("code exchange failed: %s", err.Error())
	}

	response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	fmt.Println(response)
	defer response.Body.Close()
	contents, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading response body: %s", err.Error())
	}
	var userInfo map[string]interface{}
	if err := json.Unmarshal(contents, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %s", err.Error())
	}

	return userInfo, nil
	
}