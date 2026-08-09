package ciregression

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProtobufGenerationUsesOnlyPinnedLocalTools(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	content, err := os.ReadFile(filepath.Join(root, "Makefile"))
	require.NoError(t, err)
	makefile := string(content)
	require.Contains(t, makefile, "'$(PROTO_TOOLS_DIR)/buf' generate")
	require.NotContains(t, makefile, "PATH='$(PROTO_TOOLS_DIR)':$$PATH protoc ")
	require.Contains(t, makefile, "find api cmd internal tools")
	require.Contains(t, makefile, "lint: fmt-check proto-check", "the CI lint gate must keep generated protobuf drift checking enabled")
	require.Equal(t, 2, strings.Count(makefile, "'$(PROTO_TOOLS_DIR)/buf' generate"), "proto and proto-check must use the same pinned generator")
	bufConfig, err := os.ReadFile(filepath.Join(root, "buf.gen.yaml"))
	require.NoError(t, err)
	require.Contains(t, string(bufConfig), "local: protoc-gen-go")
	require.Contains(t, string(bufConfig), "local: protoc-gen-go-grpc")
}
