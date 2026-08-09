package demoauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Credentials struct {
	Login    string
	Email    string
	Password string
}

type Client struct {
	HTTP    *http.Client
	AuthURL string
	MailURL string
}

func (c Client) ServiceToken(ctx context.Context, login, secret string) (string, error) {
	var response struct {
		AccessToken string `json:"access_token"`
	}
	if err := c.requestJSON(ctx, http.MethodPost, strings.TrimRight(c.AuthURL, "/")+"/v1/auth/service-token", map[string]string{
		"login": login, "secret": secret,
	}, &response); err != nil {
		return "", err
	}
	if response.AccessToken == "" {
		return "", fmt.Errorf("service-token response did not contain access_token")
	}
	return response.AccessToken, nil
}

func (c Client) HumanToken(ctx context.Context, credentials Credentials) (string, error) {
	seen, err := c.messageIDs(ctx)
	if err != nil {
		return "", fmt.Errorf("snapshot Mailpit messages: %w", err)
	}
	var challenge struct {
		LoginChallenge string `json:"login_challenge"`
	}
	if err := c.requestJSON(ctx, http.MethodPost, strings.TrimRight(c.AuthURL, "/")+"/v1/auth/login", map[string]string{
		"login": credentials.Login, "password": credentials.Password,
	}, &challenge); err != nil {
		return "", err
	}
	if challenge.LoginChallenge == "" {
		return "", fmt.Errorf("login response did not contain login_challenge")
	}
	code, err := c.waitForOTP(ctx, credentials.Email, seen)
	if err != nil {
		return "", err
	}
	var tokens struct {
		AccessToken string `json:"access_token"`
	}
	if err := c.requestJSON(ctx, http.MethodPost, strings.TrimRight(c.AuthURL, "/")+"/v1/auth/login/verify-otp", map[string]string{
		"challenge":    challenge.LoginChallenge,
		"code":         code,
		"device_id":    "examples-demo-" + credentials.Login,
		"device_label": "examples demo helper",
	}, &tokens); err != nil {
		return "", err
	}
	if tokens.AccessToken == "" {
		return "", fmt.Errorf("verify-otp response did not contain access_token")
	}
	return tokens.AccessToken, nil
}

type mailMessage struct {
	ID string
	To []struct{ Address string }
}

func (c Client) messageIDs(ctx context.Context) (map[string]struct{}, error) {
	var list struct {
		Messages []mailMessage `json:"messages"`
	}
	if err := c.getJSON(ctx, strings.TrimRight(c.MailURL, "/")+"/api/v1/messages?limit=50", &list); err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(list.Messages))
	for _, message := range list.Messages {
		seen[message.ID] = struct{}{}
	}
	return seen, nil
}

func (c Client) waitForOTP(ctx context.Context, email string, seen map[string]struct{}) (string, error) {
	base := strings.TrimRight(c.MailURL, "/")
	for attempt := 0; attempt < 80; attempt++ {
		var list struct {
			Messages []mailMessage `json:"messages"`
		}
		if err := c.getJSON(ctx, base+"/api/v1/messages?limit=50", &list); err == nil {
			for _, message := range list.Messages {
				if _, existed := seen[message.ID]; existed {
					continue
				}
				for _, recipient := range message.To {
					if !strings.EqualFold(recipient.Address, email) {
						continue
					}
					var detail struct{ Text string }
					if err := c.getJSON(ctx, base+"/api/v1/message/"+message.ID, &detail); err == nil {
						if code := sixDigitCode(detail.Text); code != "" {
							return code, nil
						}
					}
				}
			}
		}
		timer := time.NewTimer(125 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ctx.Err()
		case <-timer.C:
		}
	}
	return "", fmt.Errorf("OTP email for %s did not arrive", email)
}

func sixDigitCode(text string) string {
	for start := 0; start+6 <= len(text); start++ {
		candidate := text[start : start+6]
		if candidate[0] < '0' || candidate[0] > '9' {
			continue
		}
		valid := true
		for _, value := range candidate[1:] {
			valid = valid && value >= '0' && value <= '9'
		}
		if !valid {
			continue
		}
		if start > 0 && text[start-1] >= '0' && text[start-1] <= '9' {
			continue
		}
		if start+6 < len(text) && text[start+6] >= '0' && text[start+6] <= '9' {
			continue
		}
		return candidate
	}
	return ""
}

func (c Client) requestJSON(ctx context.Context, method, endpoint string, input, output any) error {
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.httpClient().Do(request)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, endpoint, err)
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("%s %s returned %d: %s", method, endpoint, response.StatusCode, strings.TrimSpace(string(content)))
	}
	if output == nil || len(bytes.TrimSpace(content)) == 0 {
		return nil
	}
	if err := json.Unmarshal(content, output); err != nil {
		return fmt.Errorf("decode %s response: %w", endpoint, err)
	}
	return nil
}

func (c Client) getJSON(ctx context.Context, endpoint string, output any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	response, err := c.httpClient().Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		return fmt.Errorf("GET %s returned %d", endpoint, response.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(output)
}

func (c Client) httpClient() *http.Client {
	client := &http.Client{Timeout: 5 * time.Second}
	if c.HTTP != nil {
		copy := *c.HTTP
		client = &copy
		if client.Timeout == 0 {
			client.Timeout = 5 * time.Second
		}
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client
}
