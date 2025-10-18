package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func runGet(args []string) error {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	urlFlag := fs.String("u", "https://localhost:8081/sgx/certification/v4/platforms", "The URL of the PCCS's GET platforms API")
	outputFile := fs.String("o", "platform_list.json", "The output file name for platform list")
	source := fs.String("s", "reg", "Source: reg, reg_na, or [FMSPC1,FMSPC2,...]")
	adminToken := fs.String("t", "", "Admin token for authentication (or set PCCS_ADMIN_TOKEN env var)")
	insecure := fs.Bool("k", false, "Skip TLS certificate verification")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: pccsadmin get [options]

Get platform registration data from PCCS service.

Options:
  -u <url>     The URL of the PCCS's GET platforms API
               Default: https://localhost:8081/sgx/certification/v4/platforms
  -o <file>    The output file name for platform list
               Default: platform_list.json
  -s <source>  Source of platforms:
               reg      - Get platforms from registration table (default)
               reg_na   - Get platforms whose PCK certs are not available
               [FMSPC1,FMSPC2,...] - Get platforms from cache by FMSPC
               []       - Get all cached platforms
  -t <token>   Admin token for authentication (or set PCCS_ADMIN_TOKEN)
  -k           Skip TLS certificate verification

Example:
  pccsadmin get -u https://localhost:8081/sgx/certification/v4/platforms -o platforms.json
  pccsadmin get -s reg_na
  pccsadmin get -s [00906EA10000,00906ED50000]
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
	baseURL := *urlFlag
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	q := parsedURL.Query()

	// Parse source parameter
	src := strings.TrimSpace(*source)
	if src == "reg" {
		q.Set("type", "registration")
	} else if src == "reg_na" {
		q.Set("type", "registration")
		q.Set("update", "na")
	} else if strings.HasPrefix(src, "[") && strings.HasSuffix(src, "]") {
		// Extract FMSPC list
		fmspcList := strings.Trim(src, "[]")
		if fmspcList != "" {
			q.Set("fmspc", fmspcList)
		}
		q.Set("type", "cache")
	} else {
		return fmt.Errorf("invalid source parameter: %s", src)
	}

	parsedURL.RawQuery = q.Encode()
	finalURL := parsedURL.String()

	fmt.Printf("Fetching platforms from: %s\n", finalURL)

	// Create HTTP client
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: *insecure,
			},
		},
	}

	// Create request
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

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Pretty print JSON for verification
	var platforms interface{}
	if err := json.Unmarshal(bodyBytes, &platforms); err != nil {
		return fmt.Errorf("failed to parse JSON response: %w", err)
	}

	// Write to output file
	prettyJSON, err := json.MarshalIndent(platforms, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format JSON: %w", err)
	}

	if err := os.WriteFile(*outputFile, prettyJSON, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	fmt.Printf("Successfully saved platform list to: %s\n", *outputFile)
	return nil
}
