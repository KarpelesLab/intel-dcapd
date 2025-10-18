package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func runPut(args []string) error {
	fs := flag.NewFlagSet("put", flag.ExitOnError)
	urlFlag := fs.String("u", "https://localhost:8081/sgx/certification/v4/platformcollateral", "The URL of the PCCS's PUT API")
	inputFile := fs.String("i", "", "The input file name for platform collaterals or appraisal policy")
	fmspc := fs.String("f", "", "FMSPC value (required for appraisal policy)")
	defaultPolicy := fs.Bool("d", false, "Make this the default policy for this FMSPC")
	adminToken := fs.String("t", "", "Admin token for authentication (or set PCCS_ADMIN_TOKEN env var)")
	insecure := fs.Bool("k", false, "Skip TLS certificate verification")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: pccsadmin put [options]

Upload platform collateral or appraisal policy to PCCS cache database.

Formats:
  1. Upload platform collateral:
     pccsadmin put -u https://localhost:8081/sgx/certification/v4/platformcollateral -i collateral.json

  2. Upload appraisal policy:
     pccsadmin put -u https://localhost:8081/sgx/certification/v4/appraisalpolicy -f <fmspc> -i policy.jwt [-d]

Options:
  -u <url>     The URL of the PCCS's PUT API
               Default: https://localhost:8081/sgx/certification/v4/platformcollateral
  -i <file>    The input file name (required)
  -f <fmspc>   FMSPC value (required for appraisal policy)
  -d           Make this the default policy for the FMSPC
  -t <token>   Admin token for authentication (or set PCCS_ADMIN_TOKEN)
  -k           Skip TLS certificate verification

Examples:
  pccsadmin put -i collateral.json
  pccsadmin put -u https://localhost:8081/sgx/certification/v4/appraisalpolicy -f 00906EA10000 -i policy.jwt -d
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate required arguments
	if *inputFile == "" {
		return fmt.Errorf("input file (-i) is required")
	}

	// Check if this is for appraisal policy
	isAppraisalPolicy := strings.Contains(*urlFlag, "/appraisalpolicy")
	if isAppraisalPolicy && *fmspc == "" {
		return fmt.Errorf("FMSPC (-f) is required for appraisal policy")
	}

	// Set default input file for platform collateral if not specified
	if *inputFile == "" && !isAppraisalPolicy {
		*inputFile = "platform_collaterals.json"
	}

	// Get admin token from env if not provided
	token := *adminToken
	if token == "" {
		token = os.Getenv("PCCS_ADMIN_TOKEN")
	}

	// Read input file
	data, err := os.ReadFile(*inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// Build URL
	finalURL := *urlFlag
	if isAppraisalPolicy {
		finalURL = fmt.Sprintf("%s?fmspc=%s", finalURL, *fmspc)
		if *defaultPolicy {
			finalURL += "&default=true"
		}
	}

	fmt.Printf("Uploading to: %s\n", finalURL)
	fmt.Printf("File size: %d bytes\n", len(data))

	// Create HTTP client
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: *insecure,
			},
		},
	}

	// Create request
	req, err := http.NewRequest("PUT", finalURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	if isAppraisalPolicy {
		req.Header.Set("Content-Type", "application/jwt")
	} else {
		req.Header.Set("Content-Type", "application/json")
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

	fmt.Printf("Successfully uploaded to PCCS\n")
	fmt.Printf("Response: %s\n", string(bodyBytes))
	return nil
}
