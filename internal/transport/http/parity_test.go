package httptransport

import (
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
	authv1 "github.com/olegkapshai/auth-master/api/auth/v1"
	"github.com/olegkapshai/auth-master/internal/config"
	"github.com/olegkapshai/auth-master/internal/transport/parity"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestHTTPAndGRPCParityManifest(t *testing.T) {
	require.Len(t, parity.BusinessRoutes, 54)
	require.Len(t, parity.TransportOnlyRoutes, 3)

	router := NewServer(&config.Config{}, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler()
	httpRoutes := map[string]int{}
	require.NoError(t, chi.Walk(router.(chi.Routes), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if method != "OPTIONS" {
			httpRoutes[method+" "+route]++
		}
		return nil
	}))
	expectedHTTPRoutes := make(map[string]int, len(parity.HTTPRoutes))
	for key := range parity.HTTPRoutes {
		expectedHTTPRoutes[key] = 1
	}
	for key, count := range httpRoutes {
		require.Equalf(t, 1, count, "HTTP route must appear exactly once: %s", key)
	}
	require.Equal(t, expectedHTTPRoutes, httpRoutes, "router and parity manifest must be an exact bijection")

	rpcs := map[string]int{}
	services := []protoreflect.ServiceDescriptor{
		authv1.File_api_auth_v1_auth_proto.Services().ByName("AuthService"),
		authv1.File_api_auth_v1_auth_proto.Services().ByName("IdentityService"),
		authv1.File_api_auth_v1_auth_proto.Services().ByName("SessionService"),
		authv1.File_api_auth_v1_auth_proto.Services().ByName("AdminService"),
		authv1.File_api_auth_v1_auth_proto.Services().ByName("RoleService"),
	}
	for _, service := range services {
		for i := 0; i < service.Methods().Len(); i++ {
			method := service.Methods().Get(i)
			rpcs["/"+string(service.FullName())+"/"+string(method.Name())]++
		}
	}
	require.Len(t, rpcs, 54)
	csrf := 0
	public := 0
	human := 0
	manifestRPCs := map[string]bool{}
	for _, route := range parity.BusinessRoutes {
		require.Equalf(t, 1, rpcs[route.RPC], "RPC must exist exactly once: %s", route.RPC)
		require.Falsef(t, manifestRPCs[route.RPC], "duplicate manifest RPC %s", route.RPC)
		manifestRPCs[route.RPC] = true
		require.Equal(t, route.Auth, parity.RPCPolicies[route.RPC])
		switch route.Auth {
		case parity.AuthPublic:
			public++
		case parity.AuthHuman:
			human++
		default:
			t.Fatalf("unclassified RPC %s", route.RPC)
		}
		if route.CSRF {
			csrf++
		}
	}
	require.Equal(t, 10, csrf)
	require.Equal(t, 16, public)
	require.Equal(t, 38, human)
	require.Equal(t, rpcs, func() map[string]int {
		out := make(map[string]int, len(manifestRPCs))
		for rpc := range manifestRPCs {
			out[rpc] = 1
		}
		return out
	}())
}
