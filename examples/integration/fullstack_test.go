package integration_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

type environment struct {
	authURL string
	mailURL string
	appURL  string
}

type authSession struct {
	client *http.Client
	token  string
	csrf   string
}

type user struct {
	id    string
	token string
}

func TestFullStackIntegration(t *testing.T) {
	example := os.Getenv("EXAMPLE_INTEGRATION")
	if example == "" {
		t.Skip("EXAMPLE_INTEGRATION is set by make test-integration")
	}
	env := environment{authURL: required(t, "INTEGRATION_AUTH_URL"), mailURL: required(t, "INTEGRATION_MAILPIT_URL"), appURL: required(t, "INTEGRATION_APP_URL")}
	switch example {
	case "minio-storage":
		testMinIOStack(t, env)
	case "deployment-api":
		testDeploymentStack(t, env)
	case "support-desk":
		testSupportStack(t, env)
	default:
		t.Fatalf("unsupported EXAMPLE_INTEGRATION %q", example)
	}
}

func testMinIOStack(t *testing.T, env environment) {
	registered := requestJSON[struct {
		UserID             string `json:"user_id"`
		ProvisioningStatus string `json:"provisioning_status"`
	}](t, http.DefaultClient, http.MethodPost, env.appURL+"/register", map[string]string{
		"login": "integration-storage", "email": "integration-storage@example.test", "password": "Integration!Storage9",
	}, "", "", http.StatusCreated)
	if registered.UserID == "" || registered.ProvisioningStatus != "ready" {
		t.Fatalf("public registration was not auto-provisioned: %#v", registered)
	}
	registeredOwner := login(t, env, "integration-storage", "integration-storage@example.test", "Integration!Storage9")
	requestJSON[map[string]any](t, http.DefaultClient, http.MethodGet, env.appURL+"/folders/"+registered.UserID, nil, registeredOwner.token, "", http.StatusOK)

	owner := login(t, env, "storage-owner", "storage-owner@example.test", "Example!Passw0rd9")
	reader := login(t, env, "storage-reader", "storage-reader@example.test", "Example!Passw0rd9")
	writer := login(t, env, "storage-writer", "storage-writer@example.test", "Example!Passw0rd9")
	stranger := login(t, env, "storage-stranger", "storage-stranger@example.test", "Example!Passw0rd9")
	identity := requestJSON[struct {
		ID string `json:"id"`
	}](t, owner.client, http.MethodGet, env.authURL+"/v1/me", nil, owner.token, "", http.StatusOK)
	listing := requestJSON[struct {
		Entries []struct {
			Name string `json:"name"`
		} `json:"entries"`
	}](t, http.DefaultClient, http.MethodGet, env.appURL+"/folders/"+identity.ID+"?path=welcome", nil, owner.token, "", http.StatusOK)
	names := make([]string, 0, len(listing.Entries))
	for _, entry := range listing.Entries {
		names = append(names, entry.Name)
	}
	if !contains(names, "readme.txt") || !contains(names, "projects") {
		t.Fatalf("seeded storage entries = %v", names)
	}
	requestJSON[map[string]any](t, http.DefaultClient, http.MethodGet, env.appURL+"/folders/"+identity.ID+"?path=welcome/projects", nil, reader.token, "", http.StatusOK)
	requestText(t, http.DefaultClient, http.MethodGet, env.appURL+"/folders/"+identity.ID, "", reader.token, "", http.StatusForbidden)
	requestText(t, http.DefaultClient, http.MethodGet, env.appURL+"/folders/"+identity.ID+"?path=welcome", "", stranger.token, "", http.StatusForbidden)
	requestText(t, http.DefaultClient, http.MethodPut, env.appURL+"/folders/"+identity.ID+"/objects/welcome/fullstack.txt", "full stack bytes", writer.token, "", http.StatusNoContent)
	content := requestText(t, http.DefaultClient, http.MethodGet, env.appURL+"/folders/"+identity.ID+"/objects/welcome/fullstack.txt", "", reader.token, "", http.StatusOK)
	if content != "full stack bytes" {
		t.Fatalf("MinIO application round trip = %q", content)
	}
	t.Log("PASS minio-storage: seeded personas traversed folder roles and authorized application Put/Get reached private MinIO")
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func testDeploymentStack(t *testing.T, env environment) {
	requestText(t, http.DefaultClient, http.MethodGet, env.appURL+"/healthz", "", "", "", http.StatusNoContent)
	developer := login(t, env, "deploy-developer", "deploy-developer@example.test", "Example!Passw0rd9")
	stranger := login(t, env, "deploy-stranger", "deploy-stranger@example.test", "Example!Passw0rd9")
	requestText(t, http.DefaultClient, http.MethodPost, env.appURL+"/apps/billing/deploy", "", developer.token, "", http.StatusNoContent)
	requestText(t, http.DefaultClient, http.MethodDelete, env.appURL+"/apps/billing", "", developer.token, "", http.StatusForbidden)
	requestText(t, http.DefaultClient, http.MethodPost, env.appURL+"/apps/billing/deploy", "", stranger.token, "", http.StatusForbidden)
	t.Log("PASS deployment-api: application called real auth-master for an allowed developer and denied delete/stranger decisions")
}

func testSupportStack(t *testing.T, env environment) {
	owner := login(t, env, "support-owner", "support-owner@example.test", "Example!Passw0rd9")
	stranger := login(t, env, "support-stranger", "support-stranger@example.test", "Example!Passw0rd9")
	seeded := requestJSON[struct {
		Tickets []struct {
			ID string `json:"id"`
		} `json:"tickets"`
	}](t, http.DefaultClient, http.MethodGet, env.appURL+"/demo/tickets", nil, "", "", http.StatusOK)
	if len(seeded.Tickets) != 1 || seeded.Tickets[0].ID == "" {
		t.Fatalf("support seed fixture is not ready: %#v", seeded)
	}
	requestJSON[map[string]any](t, http.DefaultClient, http.MethodPost, env.appURL+"/rpc", map[string]any{"Method": "GetTicket", "AccessToken": owner.token, "TicketID": seeded.Tickets[0].ID}, "", "", http.StatusOK)
	requestText(t, http.DefaultClient, http.MethodPost, env.appURL+"/rpc", encode(map[string]any{"Method": "GetTicket", "AccessToken": stranger.token, "TicketID": seeded.Tickets[0].ID}), "", "", http.StatusForbidden)
	created := requestJSON[map[string]any](t, http.DefaultClient, http.MethodPost, env.appURL+"/rpc", map[string]any{"Method": "CreateTicket", "AccessToken": owner.token, "Body": "integration ticket"}, "", "", http.StatusOK)
	ticketID, _ := created["id"].(string)
	if ticketID == "" || created["body"] != "integration ticket" {
		t.Fatalf("unexpected ticket response: %#v", created)
	}
	read := requestJSON[map[string]any](t, http.DefaultClient, http.MethodPost, env.appURL+"/rpc", map[string]any{"Method": "GetTicket", "AccessToken": owner.token, "TicketID": ticketID}, "", "", http.StatusOK)
	if read["body"] != "integration ticket" {
		t.Fatalf("unexpected ticket read: %#v", read)
	}
	requestText(t, http.DefaultClient, http.MethodPost, env.appURL+"/rpc", encode(map[string]any{"Method": "GetTicket", "AccessToken": stranger.token, "TicketID": ticketID}), "", "", http.StatusForbidden)
	missingID := "d53eeb8e-f14f-4642-b62e-c5183174d322"
	for _, check := range []struct {
		token string
		code  int
		body  string
	}{
		{token: "", code: http.StatusUnauthorized, body: "Unauthenticated\n"},
		{token: "not-a-valid-access-token", code: http.StatusUnauthorized, body: "Unauthenticated\n"},
		{token: tamperJWTSignature(t, owner.token), code: http.StatusServiceUnavailable, body: "Unavailable\n"},
	} {
		existingFailure := requestText(t, http.DefaultClient, http.MethodPost, env.appURL+"/rpc", encode(map[string]any{"Method": "GetTicket", "AccessToken": check.token, "TicketID": ticketID}), "", "", check.code)
		missingFailure := requestText(t, http.DefaultClient, http.MethodPost, env.appURL+"/rpc", encode(map[string]any{"Method": "GetTicket", "AccessToken": check.token, "TicketID": missingID}), "", "", check.code)
		if existingFailure != missingFailure || existingFailure != check.body {
			t.Fatalf("authentication failure disclosed ticket existence: existing=%q missing=%q", existingFailure, missingFailure)
		}
	}
	t.Log("PASS support-desk: HTTP adapter traversed real gRPC service/auth-master and enforced local ownership")
}

func tamperJWTSignature(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[2] == "" {
		t.Fatalf("access token is not a compact JWT")
	}
	replacement := byte('A')
	if parts[2][0] == replacement {
		replacement = 'B'
	}
	parts[2] = string(replacement) + parts[2][1:]
	return strings.Join(parts, ".")
}

func login(t *testing.T, env environment, loginName, email, password string) authSession {
	t.Helper()
	seen := mailMessageIDs(t, env.mailURL)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	challenge := requestJSON[struct {
		Challenge string `json:"login_challenge"`
	}](t, client, http.MethodPost, env.authURL+"/v1/auth/login", map[string]string{"login": loginName, "password": password}, "", "", http.StatusOK)
	code := waitForOTP(t, env.mailURL, email, seen)
	tokens := requestJSON[struct {
		Access string `json:"access_token"`
		CSRF   string `json:"csrf_token"`
	}](t, client, http.MethodPost, env.authURL+"/v1/auth/login/verify-otp", map[string]string{
		"challenge": challenge.Challenge, "code": code, "device_id": loginName + "-integration-device", "device_label": "examples integration",
	}, "", "", http.StatusOK)
	return authSession{client: client, token: tokens.Access, csrf: tokens.CSRF}
}

func createUser(t *testing.T, env environment, admin authSession, loginName, email, password string) user {
	t.Helper()
	invite := requestJSON[struct {
		Token string `json:"token"`
	}](t, admin.client, http.MethodPost, env.authURL+"/v1/admin/registration-invites", map[string]any{"email": email, "ttl_seconds": 3600, "superuser": false}, admin.token, admin.csrf, http.StatusCreated)
	registered := requestJSON[struct {
		ID string `json:"user_id"`
	}](t, http.DefaultClient, http.MethodPost, env.authURL+"/v1/auth/register", map[string]string{"invite_token": invite.Token, "login": loginName, "email": email, "password": password}, "", "", http.StatusCreated)
	return user{id: registered.ID, token: login(t, env, loginName, email, password).token}
}

func createRole(t *testing.T, env environment, admin authSession, name string) string {
	t.Helper()
	created := requestJSON[struct {
		ID string `json:"role_id"`
	}](t, admin.client, http.MethodPost, env.authURL+"/v1/roles", map[string]string{"name": name, "description": "full-stack integration", "parent_id": ""}, admin.token, admin.csrf, http.StatusCreated)
	return created.ID
}

func assignRole(t *testing.T, env environment, admin authSession, roleID, userID, level string) {
	t.Helper()
	requestText(t, admin.client, http.MethodPost, env.authURL+"/v1/roles/"+roleID+"/members", encode(map[string]any{"user_id": userID, "level": level, "valid_until": nil}), admin.token, admin.csrf, http.StatusNoContent)
}

type mailMessage struct {
	ID string
	To []struct{ Address string }
}

func mailMessageIDs(t *testing.T, mailURL string) map[string]struct{} {
	t.Helper()
	response, err := http.Get(mailURL + "/api/v1/messages?limit=50")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Mailpit message snapshot returned %d", response.StatusCode)
	}
	var list struct {
		Messages []mailMessage `json:"messages"`
	}
	if err := json.NewDecoder(response.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]struct{}, len(list.Messages))
	for _, message := range list.Messages {
		seen[message.ID] = struct{}{}
	}
	return seen
}

func waitForOTP(t *testing.T, mailURL, email string, seen map[string]struct{}) string {
	t.Helper()
	pattern := regexp.MustCompile(`\b(\d{6})\b`)
	for attempt := 0; attempt < 80; attempt++ {
		response, err := http.Get(mailURL + "/api/v1/messages?limit=50")
		if err == nil && response.StatusCode == http.StatusOK {
			var list struct {
				Messages []mailMessage `json:"messages"`
			}
			decodeErr := json.NewDecoder(response.Body).Decode(&list)
			response.Body.Close()
			if decodeErr == nil {
				for _, message := range list.Messages {
					if _, existed := seen[message.ID]; existed {
						continue
					}
					for _, recipient := range message.To {
						if strings.EqualFold(recipient.Address, email) {
							detail, detailErr := http.Get(mailURL + "/api/v1/message/" + message.ID)
							if detailErr == nil && detail.StatusCode == http.StatusOK {
								var content struct{ Text string }
								_ = json.NewDecoder(detail.Body).Decode(&content)
								detail.Body.Close()
								if match := pattern.FindStringSubmatch(content.Text); len(match) == 2 {
									return match[1]
								}
							}
						}
					}
				}
			}
		} else if response != nil {
			response.Body.Close()
		}
		time.Sleep(125 * time.Millisecond)
	}
	t.Fatalf("OTP for %s did not arrive", email)
	return ""
}

func requestJSON[T any](t *testing.T, client *http.Client, method, endpoint string, body any, token, csrf string, status int) T {
	t.Helper()
	text := ""
	if body != nil {
		text = encode(body)
	}
	content := requestText(t, client, method, endpoint, text, token, csrf, status)
	var output T
	if content != "" {
		if err := json.Unmarshal([]byte(content), &output); err != nil {
			t.Fatalf("decode %s: %v; body=%s", endpoint, err, content)
		}
	}
	return output
}

func requestText(t *testing.T, client *http.Client, method, endpoint, body, token, csrf string, expected int) string {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request, err := http.NewRequest(method, endpoint, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, endpoint, err)
	}
	defer response.Body.Close()
	content, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != expected {
		t.Fatalf("%s %s returned %d, want %d: %s", method, endpoint, response.StatusCode, expected, content)
	}
	return string(content)
}

func encode(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		panic(fmt.Sprintf("encode integration request: %v", err))
	}
	return string(bytes.TrimSpace(data))
}

func required(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}
