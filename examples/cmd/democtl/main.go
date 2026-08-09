package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/olegkapshai/auth-master/examples/internal/demoauth"
	"github.com/olegkapshai/auth-master/examples/internal/demoseed"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) != 2 {
		log.Fatal("usage: democtl seed|token|personas")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	example := required("EXAMPLE")
	plan, err := demoseed.PlanFor(example)
	if err != nil {
		log.Fatal(err)
	}
	switch os.Args[1] {
	case "seed":
		var result demoseed.Result
		result, err = demoseed.Run(ctx, demoseed.Config{
			Example: example, AuthHTTPURL: required("AUTH_HTTP_URL"), AuthGRPCAddr: required("AUTH_GRPC_ADDR"),
			MailpitURL: required("MAILPIT_URL"), AppURL: required("APP_URL"),
			ServiceLogin: required("AUTH_SERVICE_LOGIN"), ServiceSecret: required("AUTH_SERVICE_SECRET"),
		})
		if err == nil {
			fmt.Printf("PASS %s demo personas, roles, and fixtures are ready\n", example)
			if example == "minio-storage" {
				fmt.Printf("Workspace: %s/?owner=%s&path=welcome\n", strings.TrimRight(required("PUBLIC_APP_URL"), "/"), result.Users["owner"])
			}
		}
	case "token":
		key := required("PERSONA")
		persona, ok := plan.Persona(key)
		if !ok {
			log.Fatalf("unknown %s persona %q", example, key)
		}
		var token string
		token, err = (demoauth.Client{AuthURL: required("AUTH_HTTP_URL"), MailURL: required("MAILPIT_URL")}).HumanToken(ctx, persona.Credentials())
		if err == nil {
			fmt.Println(token)
		}
	case "personas":
		for _, persona := range plan.Personas {
			fmt.Printf("%-10s %-20s %-32s %s\n", persona.Key, persona.Login, demoseed.DemoPassword, persona.Capabilities)
		}
	default:
		log.Fatalf("unknown command %q", os.Args[1])
	}
	if err != nil {
		log.Fatal(err)
	}
}

func required(name string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		log.Fatalf("%s is required", name)
	}
	return value
}
