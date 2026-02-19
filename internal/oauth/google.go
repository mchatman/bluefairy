package oauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	googleAuthURL     = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL    = "https://oauth2.googleapis.com/token"
	googleUserInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"
)

var googleScopes = strings.Join([]string{
	"https://www.googleapis.com/auth/gmail.modify",
	"https://www.googleapis.com/auth/calendar",
	"https://www.googleapis.com/auth/drive.readonly",
	"https://www.googleapis.com/auth/contacts.readonly",
	"https://www.googleapis.com/auth/userinfo.email",
}, " ")

// GoogleProvider implements Provider for Google OAuth 2.0.
type GoogleProvider struct {
	clientID     string
	clientSecret string
	redirectURI  string
}

// NewGoogleProvider creates a Google OAuth provider.
func NewGoogleProvider(clientID, clientSecret, redirectURI string) *GoogleProvider {
	return &GoogleProvider{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURI:  redirectURI,
	}
}

func (g *GoogleProvider) Name() string { return "google" }

func (g *GoogleProvider) BuildAuthURL(state string) string {
	params := url.Values{
		"client_id":     {g.clientID},
		"redirect_uri":  {g.redirectURI},
		"response_type": {"code"},
		"scope":         {googleScopes},
		"access_type":   {"offline"},
		"prompt":        {"consent select_account"},
		"state":         {state},
	}
	return googleAuthURL + "?" + params.Encode()
}

func (g *GoogleProvider) ExchangeCode(code string) (*TokenResponse, error) {
	body := url.Values{
		"code":          {code},
		"client_id":     {g.clientID},
		"client_secret": {g.clientSecret},
		"redirect_uri":  {g.redirectURI},
		"grant_type":    {"authorization_code"},
	}
	return g.postToken(body)
}

func (g *GoogleProvider) RefreshAccessToken(refreshToken string) (*TokenResponse, error) {
	body := url.Values{
		"refresh_token": {refreshToken},
		"client_id":     {g.clientID},
		"client_secret": {g.clientSecret},
		"grant_type":    {"refresh_token"},
	}
	return g.postToken(body)
}

func (g *GoogleProvider) GetEmail(accessToken string) (string, error) {
	req, _ := http.NewRequest(http.MethodGet, googleUserInfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("google userinfo request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("google userinfo failed (%d)", resp.StatusCode)
	}

	var info struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", fmt.Errorf("decoding userinfo: %w", err)
	}
	return info.Email, nil
}

func (g *GoogleProvider) postToken(body url.Values) (*TokenResponse, error) {
	resp, err := http.PostForm(googleTokenURL, body)
	if err != nil {
		return nil, fmt.Errorf("google token request: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google token failed (%d): %s", resp.StatusCode, raw)
	}

	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(raw, &tok); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}
	return &TokenResponse{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		ExpiresIn:    tok.ExpiresIn,
		Scope:        tok.Scope,
	}, nil
}
