package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

func runFetch(args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ExitOnError)
	urlFlag := fs.String("u", "https://api.trustedservices.intel.com/sgx/certification/v4/", "The URL of the Intel PCS service")
	inputFile := fs.String("i", "platform_list.json", "The input file name for platform list")
	outputFile := fs.String("o", "platform_collaterals.json", "The output file name for platform collaterals")
	_ = fs.String("t", "standard", "Type of update: standard, early, or all")
	apiKey := fs.String("k", "", "Intel PCS API key (or set INTEL_API_KEY env var)")
	crlOnly := fs.Bool("c", false, "Retrieve only the certificate revocation list (CRL)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: pccsadmin fetch [options]

Fetch platform collateral data from Intel PCS based on registration data.

Options:
  -u <url>     The URL of the Intel PCS service
               Default: https://api.trustedservices.intel.com/sgx/certification/v4/
  -i <file>    The input file name for platform list
               Default: platform_list.json
  -o <file>    The output file name for platform collaterals
               Default: platform_collaterals.json
  -t <type>    Type of TCB update: standard, early, or all
               Default: standard
  -k <key>     Intel PCS API key (or set INTEL_API_KEY env var)
  -c           Retrieve only CRL (ignores input file if provided)

Examples:
  pccsadmin fetch -i platforms.json -o collateral.json -k YOUR_API_KEY
  pccsadmin fetch -t early -i platforms.json
  pccsadmin fetch -c -k YOUR_API_KEY
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Get API key from env if not provided
	key := *apiKey
	if key == "" {
		key = os.Getenv("INTEL_API_KEY")
	}
	if key == "" {
		return fmt.Errorf("Intel API key is required (use -k flag or set INTEL_API_KEY environment variable)")
	}

	if *crlOnly {
		return fetchCRLOnly(*urlFlag, key, *outputFile)
	}

	// Read platform list
	data, err := os.ReadFile(*inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	var platforms []map[string]interface{}
	if err := json.Unmarshal(data, &platforms); err != nil {
		return fmt.Errorf("failed to parse platform list: %w", err)
	}

	if len(platforms) == 0 {
		return fmt.Errorf("no platforms found in input file")
	}

	fmt.Printf("Fetching collateral for %d platforms from Intel PCS...\n", len(platforms))

	// This is a simplified implementation
	// A full implementation would need to:
	// 1. Extract unique FMSPCs from platforms
	// 2. Fetch PCK certs for each platform
	// 3. Fetch TCB info for each FMSPC
	// 4. Fetch enclave identities
	// 5. Fetch CRLs
	// 6. Build the complete collateral JSON structure

	fmt.Printf("Note: Full fetch implementation requires complex PCS API interactions.\n")
	fmt.Printf("For now, please use the Intel PCCS or original Python tool for fetch operations.\n")
	fmt.Printf("You can use 'pccsadmin put' to upload manually created collateral files.\n")

	return nil
}

func fetchCRLOnly(baseURL, apiKey, outputFile string) error {
	fmt.Printf("Fetching CRLs from Intel PCS...\n")

	client := &http.Client{}
	collateral := make(map[string]interface{})

	// Fetch processor CRL
	processorCRLURL := baseURL + "pckcrl?ca=processor"
	processorCRL, err := fetchURL(client, processorCRLURL, apiKey)
	if err != nil {
		fmt.Printf("Warning: Failed to fetch processor CRL: %v\n", err)
	} else {
		collateral["processorCrl"] = processorCRL
		fmt.Printf("Fetched processor CRL\n")
	}

	// Fetch platform CRL
	platformCRLURL := baseURL + "pckcrl?ca=platform"
	platformCRL, err := fetchURL(client, platformCRLURL, apiKey)
	if err != nil {
		fmt.Printf("Warning: Failed to fetch platform CRL: %v\n", err)
	} else {
		collateral["platformCrl"] = platformCRL
		fmt.Printf("Fetched platform CRL\n")
	}

	// Fetch root CA CRL
	rootCRLURL := baseURL + "rootcacrl"
	rootCRL, err := fetchURL(client, rootCRLURL, apiKey)
	if err != nil {
		fmt.Printf("Warning: Failed to fetch root CA CRL: %v\n", err)
	} else {
		collateral["rootcacrl"] = rootCRL
		fmt.Printf("Fetched root CA CRL\n")
	}

	// Save to file
	output, err := json.MarshalIndent(collateral, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := os.WriteFile(outputFile, output, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	fmt.Printf("Successfully saved CRLs to: %s\n", outputFile)
	return nil
}

func fetchURL(client *http.Client, urlStr, apiKey string) (string, error) {
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Ocp-Apim-Subscription-Key", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// URL encode the response
	return url.QueryEscape(string(bodyBytes)), nil
}
