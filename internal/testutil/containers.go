package testutil

import "os/exec"

// OCIProviderAvailable is true when Podman or Docker responds to `info` (enough for Testcontainers).
func OCIProviderAvailable() bool {
	if exec.Command("podman", "info").Run() == nil {
		return true
	}
	return exec.Command("docker", "info").Run() == nil
}
