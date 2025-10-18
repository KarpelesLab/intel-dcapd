package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/KarpelesLab/intel-dcapd/cache"
	"github.com/KarpelesLab/intel-dcapd/maintenance"
	"github.com/KarpelesLab/intel-dcapd/pckcertselect"
	"github.com/KarpelesLab/intel-dcapd/pcs"
)

// Global verbose flag
var verbose bool

// logVerbose logs a message only if verbose mode is enabled
func logVerbose(format string, v ...interface{}) {
	if verbose {
		log.Printf("[VERBOSE] "+format, v...)
	}
}

func main() {
	// Required: Intel API Key
	apiKey := os.Getenv("INTEL_API_KEY")
	if apiKey == "" {
		log.Fatal("INTEL_API_KEY environment variable is required")
	}

	// Optional environment variables with defaults
	listenAddr := getEnv("DCAPD_LISTEN", "localhost:8081")
	cacheDir := getEnv("DCAPD_CACHE_DIR", defaultCacheDir())
	pcsURL := getEnv("DCAPD_PCS_URL", "https://api.trustedservices.intel.com/sgx/certification/v4/")
	cacheMode := getEnv("DCAPD_CACHE_MODE", "LAZY")

	// Enable verbose logging if requested
	if os.Getenv("DCAPD_VERBOSE") == "1" || os.Getenv("DCAPD_VERBOSE") == "true" {
		verbose = true
		pckcertselect.SetVerbose(true)
		log.Printf("Verbose logging enabled")
	}

	// Database is stored in cachedb subdirectory
	dbPath := filepath.Join(cacheDir, "cachedb")

	log.Printf("Starting Intel DCAP Provisioning Certificate Caching Service")
	log.Printf("Listen address: %s", listenAddr)
	log.Printf("Cache directory: %s", cacheDir)
	log.Printf("Database path: %s", dbPath)
	log.Printf("Cache mode: %s", cacheMode)

	// Initialize database
	db, err := cache.Open(dbPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Initialize Intel PCS client
	pcsClient := pcs.NewClient(apiKey, pcsURL)

	// Start background maintenance goroutine
	go maintenance.Start(db, pcsClient)

	// Setup HTTP handlers
	handler := setupHandlers(db, pcsClient, cacheMode)

	// Create HTTPS server
	server := &http.Server{
		Addr:      listenAddr,
		Handler:   handler,
		TLSConfig: getTLSConfig(),
		// Timeouts
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Get or generate TLS certificate
	tlsCert, err := getOrGenerateCert()
	if err != nil {
		log.Fatalf("Failed to get TLS certificate: %v", err)
	}

	server.TLSConfig.Certificates = []tls.Certificate{tlsCert}

	log.Printf("Server starting on https://%s", listenAddr)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func defaultCacheDir() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		// Fallback to current directory
		return "./intel-dcapd-cache"
	}
	return filepath.Join(cacheDir, "intel-dcapd")
}

func getTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}
}
