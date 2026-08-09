package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type HTTPChecker struct {
	BaseURL string
	Client  *http.Client
	Timeout time.Duration
}

func (c HTTPChecker) HasRole(ctx context.Context, token, role string) (bool, error) {
	var response struct {
		HasRole bool `json:"has_role"`
	}
	err := c.post(ctx, "/v1/auth/has-role", map[string]string{
		"token": token, "role_name": role,
	}, &response)
	return response.HasRole, err
}

func (c HTTPChecker) HasRoleWithTag(ctx context.Context, token, role, tag string) (bool, error) {
	var response struct {
		HasRoleWithTag bool `json:"has_role_with_tag"`
	}
	err := c.post(ctx, "/v1/auth/has-role-with-tag", map[string]string{
		"token": token, "role_name": role, "tag": tag,
	}, &response)
	return response.HasRoleWithTag, err
}

func (c HTTPChecker) post(ctx context.Context, endpoint string, body any, output any) error {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	if c.Client != nil {
		*client = *c.Client
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("auth-master %s: status %d: %s", endpoint, response.StatusCode, strings.TrimSpace(string(message)))
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode auth-master response: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return fmt.Errorf("decode auth-master response: %w", err)
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}
