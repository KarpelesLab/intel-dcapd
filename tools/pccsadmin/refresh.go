package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func runRefresh(args []string) error {
	fs := flag.NewFlagSet("refresh", flag.ExitOnError)
	urlFlag := fs.String("u", "https://localhost:8081/sgx/certification/v4/refresh", "The URL of the PCCS's refresh API")
	fmspc := fs.String("f", "", "FMSPC values to refresh (comma-separated) or 'all'")
	adminToken := fs.String("t", "", "Admin token for authentication (or set PCCS_ADMIN_TOKEN env var)")
	insecure := fs.Bool("k", false, "Skip TLS certificate verification")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: pccsadmin refresh [options]

Request PCCS to refresh certificates or collateral in cache database.

Options:
  -u <url>     The URL of the PCCS's refresh API
               Default: https://localhost:8081/sgx/certification/v4/refresh
  -f <fmspc>   FMSPC values to refresh:
               (empty)  - Refresh quote verification collateral (default)
               all      - Refresh all cached certificates
               FMSPC1,FMSPC2,... - Refresh certificates for specific FMSPCs
  -t <token>   Admin token for authentication (or set PCCS_ADMIN_TOKEN)
  -k           Skip TLS certificate verification

Examples:
  pccsadmin refresh
  pccsadmin refresh -f all
  pccsadmin refresh -f 00906EA10000,00906ED50000
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Get admin token from env if not provided
	token := *adminToken
	if token == "" {
		token = os.Getenv("PCCS_ADMIN_TOKEN")
	}

	// Build URL with query parameters
	finalURL := *urlFlag
	if *fmspc != "" {
		fmspcList := strings.TrimSpace(*fmspc)
		if fmspcList == "all" {
			finalURL += "?type=certs"
		} else {
			finalURL += "?type=certs&fmspc=" + fmspcList
		}
	} else {
		finalURL += "?type=collateral"
	}

	fmt.Printf("Requesting refresh from: %s\n", finalURL)

	// Create HTTP client
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: *insecure,
			},
		},
	}

	// Create request (can use GET or POST)
	req, err := http.NewRequest("GET", finalURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add authentication header if token provided
	if token != "" {
		req.Header.Set("admin-token", token)
	}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	fmt.Printf("Successfully requested refresh\n")
	fmt.Printf("Response: %s\n", string(bodyBytes))
	return nil
}
