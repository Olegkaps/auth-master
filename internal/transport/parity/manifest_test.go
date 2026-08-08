package parity

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMustHTTPRoutesRejectsMalformedManifest(t *testing.T) {
	tests := map[string]struct {
		business  []Route
		transport []Route
	}{
		"missing method": {
			business: []Route{{HTTPPath: "/v1/test", RPC: "/test.Service/Method", Auth: AuthPublic}},
		},
		"missing path": {
			business: []Route{{HTTPMethod: "GET", RPC: "/test.Service/Method", Auth: AuthPublic}},
		},
		"business missing RPC": {
			business: []Route{{HTTPMethod: "GET", HTTPPath: "/v1/test", Auth: AuthPublic}},
		},
		"business missing authentication policy": {
			business: []Route{{HTTPMethod: "GET", HTTPPath: "/v1/test", RPC: "/test.Service/Method"}},
		},
		"transport has business semantics": {
			transport: []Route{{HTTPMethod: "GET", HTTPPath: "/healthz", RPC: "/test.Service/Method", Auth: AuthPublic}},
		},
		"duplicate method and path": {
			business:  []Route{{HTTPMethod: "GET", HTTPPath: "/shared", RPC: "/test.Service/Method", Auth: AuthPublic}},
			transport: []Route{{HTTPMethod: "GET", HTTPPath: "/shared", Auth: AuthUnknown}},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			require.Panics(t, func() { mustHTTPRoutes(test.business, test.transport) })
		})
	}
}
