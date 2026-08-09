package examples_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestModuleAndComposeIsolation(t *testing.T) {
	root, err := filepath.Abs("..")
	require.NoError(t, err)
	command := exec.Command("go", "list", "./...")
	command.Dir = root
	output, err := command.CombinedOutput()
	require.NoError(t, err, string(output))
	require.NotContains(t, string(output), "/examples")
	command = exec.Command("go", "list", "-deps", "./cmd/authd")
	command.Dir = root
	output, err = command.CombinedOutput()
	require.NoError(t, err, string(output))
	require.NotContains(t, strings.ToLower(string(output)), "minio")

	ports := map[string][]string{
		"minio-storage":  {"MINIO_STORAGE_PORT:-8191", "MINIO_AUTH_PORT:-8291", "MINIO_MAILPIT_PORT:-8391"},
		"deployment-api": {"DEPLOYMENT_API_PORT:-8192", "DEPLOYMENT_AUTH_PORT:-8292", "DEPLOYMENT_MAILPIT_PORT:-8392"},
		"support-desk":   {"SUPPORT_DESK_PORT:-8193", "SUPPORT_AUTH_PORT:-8293", "SUPPORT_MAILPIT_PORT:-8393"},
	}
	for _, example := range []string{"minio-storage", "deployment-api", "support-desk"} {
		content, readErr := os.ReadFile(filepath.Join(example, "docker-compose.yml"))
		require.NoError(t, readErr)
		text := string(content)
		for _, service := range []string{"postgres:", "mailpit:", "authd:", "app:", "seed:"} {
			require.Contains(t, text, service, example)
		}
		require.Contains(t, text, "BOOTSTRAP_SUPERUSER_SERVICE_LOGIN", example)
		require.Contains(t, text, "BOOTSTRAP_SUPERUSER_SERVICE_SECRET", example)
		require.Contains(t, text, "target: demo-tools", example)
		require.Contains(t, text, "condition: service_healthy", example)
		require.Contains(t, text, "tmpfs:", example)
		require.Contains(t, text, "@sha256:", example)
		require.Contains(t, text, "healthcheck:", example)
		require.Contains(t, text, "condition: service_healthy", example)
		for _, port := range ports[example] {
			require.Contains(t, text, port, example)
		}
		if example == "minio-storage" {
			require.Contains(t, text, "  minio:")
			require.NotContains(t, text, "9000:9000")
			require.Contains(t, text, "PUBLIC_URL: http://127.0.0.1:${MINIO_STORAGE_PORT:-8191}")
		} else {
			require.NotContains(t, text, "  minio:")
		}
	}
	for _, dockerfile := range []string{"Dockerfile", "Authd.Dockerfile"} {
		content, readErr := os.ReadFile(dockerfile)
		require.NoError(t, readErr)
		require.Contains(t, string(content), "@sha256:", dockerfile)
	}
}

func TestDocumentedDemoLifecycleUsesMakeAndPublishedHostPorts(t *testing.T) {
	makefile, err := os.ReadFile("Makefile")
	require.NoError(t, err)
	for _, target := range []string{"up:", "seed:", "token:", "down:", "reset:"} {
		require.Contains(t, string(makefile), target)
	}
	require.NotContains(t, string(makefile), "up -d --build app", "stack lifecycle must rebuild authd so bootstrap/API changes cannot use a stale image")
	readme, err := os.ReadFile("README.md")
	require.NoError(t, err)
	require.Contains(t, string(readme), "make -C examples up EXAMPLE=deployment-api")
	require.Contains(t, string(readme), "make -C examples token EXAMPLE=deployment-api PERSONA=developer")
	deployment, err := os.ReadFile(filepath.Join("deployment-api", "README.md"))
	require.NoError(t, err)
	require.Contains(t, string(deployment), "http://127.0.0.1:8192/apps/billing/deploy")
	require.NotContains(t, string(deployment), "localhost:8092/apps/")
}
