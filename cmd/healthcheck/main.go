package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	target := "http://127.0.0.1:8080/healthz"
	if len(os.Args) == 2 {
		target = os.Args[1]
	}
	client := http.Client{Timeout: 2 * time.Second}
	if err := check(&client, target); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func check(client *http.Client, target string) error {
	response, err := client.Get(target)
	if err != nil {
		return err
	}
	_ = response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("health status %d", response.StatusCode)
	}
	return nil
}
