package main

import (
	"context"
	"fmt"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/olegkapshai/auth-master/internal/mcpserver"
)

func main() {
	if err := run(context.Background()); err != nil {
		// MCP stdio reserves stdout for protocol messages.
		_, _ = fmt.Fprintln(os.Stderr, "auth-master-mcp:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	cfg, err := mcpserver.ConfigFromEnv()
	if err != nil {
		return err
	}
	client, err := mcpserver.Dial(ctx, cfg)
	if err != nil {
		return err
	}
	defer client.Close()
	return mcpserver.New(client).Run(ctx, &mcp.StdioTransport{})
}
