package pcs

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is an HTTP client for Intel Provisioning Certificate Service
type Client struct {
	apiKey     string
	baseURL    string
	pcsVersion string // The version configured in baseURL (3 or 4)
	client     *http.Client
}

// NewClient creates a new Intel PCS client
func NewClient(apiKey, baseURL string) *Client {
	// Determine PCS version from baseURL
	pcsVersion := "4"
	if strings.Contains(baseURL, "/v3/") {
		pcsVersion = "3"
	} else if strings.Contains(baseURL, "/v4/") {
		pcsVersion = "4"
	}

	return &Client{
		apiKey:     apiKey,
		baseURL:    strings.TrimSuffix(baseURL, "/"),
		pcsVersion: pcsVersion,
		client: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

// Response represents a response from Intel PCS
type Response struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

// doRequest performs an HTTP request with retry logic
func (c *Client) doRequest(method, path string, query url.Values) (*Response, error) {
	urlStr := c.baseURL + path
	if len(query) > 0 {
		urlStr += "?" + query.Encode()
	}

	var lastErr error
	maxRetries := 6

	for retry := 0; retry <= maxRetries; retry++ {
		if retry > 0 {
			// Exponential backoff: 1s, 2s, 4s, 8s, 16s, 32s
			backoff := time.Duration(1<<uint(retry-1)) * time.Second
			log.Printf("Retrying request to %s after %v (attempt %d/%d)", path, backoff, retry+1, maxRetries+1)
			time.Sleep(backoff)
		}

		req, err := http.NewRequest(method, urlStr, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		// Add API key header
		req.Header.Set("Ocp-Apim-Subscription-Key", c.apiKey)

		resp, err := c.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		// Log request ID for debugging
		if requestID := resp.Header.Get("Request-Id"); requestID != "" {
			log.Printf("Intel PCS Request-ID: %s (status: %d)", requestID, resp.StatusCode)
		}

		// Return response even on non-200 status codes
		return &Response{
			StatusCode: resp.StatusCode,
			Headers:    resp.Header,
			Body:       body,
		}, nil
	}

	return nil, fmt.Errorf("request failed after %d retries: %w", maxRetries, lastErr)
}

// GetPCKCerts retrieves all PCK certificates for a platform
func (c *Client) GetPCKCerts(encPPID, pceID string) (*Response, error) {
	query := url.Values{}
	query.Set("encrypted_ppid", encPPID)
	query.Set("pceid", pceID)

	return c.doRequest("GET", "/pckcerts", query)
}

// GetPCKCertsWithManifest retrieves PCK certificates using platform manifest
func (c *Client) GetPCKCertsWithManifest(platformManifest, pceID string) (*Response, error) {
	// This requires POST, which we'll implement when needed
	// For now, return error
	return nil, fmt.Errorf("platform manifest method not yet implemented")
}

// GetPCKCRL retrieves PCK CRL
func (c *Client) GetPCKCRL(ca string) (*Response, error) {
	query := url.Values{}
	query.Set("ca", strings.ToLower(ca))
	query.Set("encoding", "der")

	return c.doRequest("GET", "/pckcrl", query)
}

// GetTCBInfo retrieves TCB information for an FMSPC
func (c *Client) GetTCBInfo(prodType, fmspc, requestVersion, updateType string) (*Response, error) {
	query := url.Values{}
	query.Set("fmspc", fmspc)
	if updateType == "early" {
		query.Set("update", "early")
	} else {
		query.Set("update", "standard")
	}

	// Start with base URL path
	path := c.baseURL + "/tcb"

	// Handle TDX vs SGX
	if prodType == "tdx" {
		path = strings.Replace(path, "/sgx/", "/tdx/", 1)
	}

	// Handle version translation: if PCS is configured for v4 but client requests v3
	if c.pcsVersion == "4" && requestVersion == "3" {
		path = strings.Replace(path, "/v4/", "/v3/", 1)
	}

	// Extract just the path component (remove baseURL prefix)
	if strings.HasPrefix(path, c.baseURL) {
		path = strings.TrimPrefix(path, c.baseURL)
	}

	return c.doRequest("GET", path, query)
}

// GetEnclaveIdentity retrieves enclave identity (QE, QVE, or TDQE)
func (c *Client) GetEnclaveIdentity(id, requestVersion, updateType string) (*Response, error) {
	query := url.Values{}
	if updateType == "early" {
		query.Set("update", "early")
	} else {
		query.Set("update", "standard")
	}

	// Start with configured base URL
	var path string
	switch id {
	case "1": // QE
		path = c.baseURL + "/qe/identity"
	case "2": // QVE
		path = c.baseURL + "/qve/identity"
	case "3": // TDQE (TDX)
		path = strings.Replace(c.baseURL, "/sgx/", "/tdx/", 1) + "/qe/identity"
	default:
		return nil, fmt.Errorf("invalid enclave identity ID: %s", id)
	}

	// Handle version translation: if PCS is configured for v4 but client requests v3
	if c.pcsVersion == "4" && requestVersion == "3" {
		path = strings.Replace(path, "/v4/", "/v3/", 1)
	}

	// Extract just the path component (remove baseURL prefix)
	if strings.HasPrefix(path, c.baseURL) {
		path = strings.TrimPrefix(path, c.baseURL)
	}

	return c.doRequest("GET", path, query)
}

// GetRootCACRL retrieves root CA CRL
func (c *Client) GetRootCACRL(rootca string) (*Response, error) {
	query := url.Values{}
	query.Set("rootca", strings.ToLower(rootca))
	query.Set("encoding", "der")

	return c.doRequest("GET", "/rootcacrl", query)
}

// GetCRL retrieves a CRL from a specific URL
func (c *Client) GetCRL(crlURL string) (*Response, error) {
	req, err := http.NewRequest("GET", crlURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
	}, nil
}

// GetTCBInfoForSGX is a convenience method for SGX TCB info
func (c *Client) GetTCBInfoForSGX(fmspc, requestVersion, updateType string) (*Response, error) {
	return c.GetTCBInfo("sgx", fmspc, requestVersion, updateType)
}

// GetTCBInfoForTDX is a convenience method for TDX TCB info
func (c *Client) GetTCBInfoForTDX(fmspc, requestVersion, updateType string) (*Response, error) {
	return c.GetTCBInfo("tdx", fmspc, requestVersion, updateType)
}
