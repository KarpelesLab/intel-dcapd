package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/KarpelesLab/intel-dcapd/cache"
	"github.com/KarpelesLab/intel-dcapd/pcs"
	"github.com/KarpelesLab/intel-dcapd/pckcertselect"
)

// extractAPIVersion extracts the API version from the request path
func extractAPIVersion(path string) string {
	if strings.Contains(path, "/v4/") {
		return "4"
	}
	if strings.Contains(path, "/v3/") {
		return "3"
	}
	return "4" // default
}

// setupHandlers configures all HTTP routes
func setupHandlers(db *cache.DB, pcsClient *pcs.Client, cacheMode string) http.Handler {
	mux := http.NewServeMux()
	auth := newAuthMiddleware()

	// SGX Certification v4 endpoints
	mux.HandleFunc("GET /sgx/certification/v4/pckcert", handlePCKCert(db, pcsClient, cacheMode))
	mux.HandleFunc("GET /sgx/certification/v4/tcb", handleTCB(db, pcsClient, "sgx"))
	mux.HandleFunc("GET /sgx/certification/v4/qe/identity", handleIdentity(db, pcsClient, cache.IdentityQE))
	mux.HandleFunc("GET /sgx/certification/v4/qve/identity", handleIdentity(db, pcsClient, cache.IdentityQVE))
	mux.HandleFunc("GET /sgx/certification/v4/pckcrl", handlePCKCRL(db, pcsClient))
	mux.HandleFunc("GET /sgx/certification/v4/rootcacrl", handleRootCACRL(db, pcsClient))
	mux.HandleFunc("GET /sgx/certification/v4/crl", handleGenericCRL(db, pcsClient))

	// Platform registration endpoints (with auth)
	mux.HandleFunc("POST /sgx/certification/v4/platforms", auth.validateUser(handleRegisterPlatforms(db, pcsClient, cacheMode)))
	mux.HandleFunc("GET /sgx/certification/v4/platforms", auth.validateAdmin(handleGetPlatforms(db)))

	// Admin endpoints
	mux.HandleFunc("PUT /sgx/certification/v4/platformcollateral", auth.validateAdmin(handlePlatformCollateral(db)))
	mux.HandleFunc("GET /sgx/certification/v4/refresh", auth.validateAdmin(handleRefresh(db, pcsClient)))

	// TDX Certification v4 endpoints
	mux.HandleFunc("GET /tdx/certification/v4/tcb", handleTCB(db, pcsClient, "tdx"))
	mux.HandleFunc("GET /tdx/certification/v4/qe/identity", handleIdentity(db, pcsClient, cache.IdentityTDQE))

	// SGX Certification v3 endpoints (for compatibility)
	mux.HandleFunc("GET /sgx/certification/v3/pckcert", handlePCKCert(db, pcsClient, cacheMode))
	mux.HandleFunc("GET /sgx/certification/v3/tcb", handleTCB(db, pcsClient, "sgx"))
	mux.HandleFunc("GET /sgx/certification/v3/qe/identity", handleIdentity(db, pcsClient, cache.IdentityQE))
	mux.HandleFunc("GET /sgx/certification/v3/qve/identity", handleIdentity(db, pcsClient, cache.IdentityQVE))
	mux.HandleFunc("GET /sgx/certification/v3/pckcrl", handlePCKCRL(db, pcsClient))
	mux.HandleFunc("GET /sgx/certification/v3/rootcacrl", handleRootCACRL(db, pcsClient))
	mux.HandleFunc("GET /sgx/certification/v3/crl", handleGenericCRL(db, pcsClient))
	mux.HandleFunc("POST /sgx/certification/v3/platforms", auth.validateUser(handleRegisterPlatforms(db, pcsClient, cacheMode)))
	mux.HandleFunc("GET /sgx/certification/v3/platforms", auth.validateAdmin(handleGetPlatforms(db)))
	mux.HandleFunc("PUT /sgx/certification/v3/platformcollateral", auth.validateAdmin(handlePlatformCollateral(db)))
	mux.HandleFunc("GET /sgx/certification/v3/refresh", auth.validateAdmin(handleRefresh(db, pcsClient)))

	return addLogging(mux)
}

// handlePCKCert handles PCK certificate requests
func handlePCKCert(db *cache.DB, pcsClient *pcs.Client, cacheMode string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse and validate parameters
		qeID := strings.ToUpper(r.URL.Query().Get("qeid"))
		cpuSVN := strings.ToUpper(r.URL.Query().Get("cpusvn"))
		pceSVN := strings.ToUpper(r.URL.Query().Get("pcesvn"))
		pceID := strings.ToUpper(r.URL.Query().Get("pceid"))
		encPPID := strings.ToUpper(r.URL.Query().Get("encrypted_ppid"))

		// Validate required parameters
		if qeID == "" || cpuSVN == "" || pceSVN == "" || pceID == "" {
			http.Error(w, "Missing required parameters", http.StatusBadRequest)
			return
		}

		// Validate parameter lengths
		if len(qeID) > 260 || len(cpuSVN) != 32 || len(pceSVN) != 4 || len(pceID) != 4 {
			http.Error(w, "Invalid parameter length", http.StatusBadRequest)
			return
		}

		if encPPID != "" && len(encPPID) != 768 {
			http.Error(w, "Invalid encrypted_ppid length", http.StatusBadRequest)
			return
		}

		// Try to get platform from cache
		platform, err := db.GetPlatform(qeID, pceID)
		if err != nil {
			log.Printf("Error getting platform: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Check if we have a matching cert in cache
		tcbm, _ := db.GetPlatformTCB(qeID, pceID, cpuSVN, pceSVN)
		if tcbm != "" {
			cert, err := db.GetCert(qeID, pceID, tcbm)
			if err == nil && cert != nil && platform != nil {
				// Cache hit!
				writePCKCertResponse(w, cert, tcbm, platform, db)
				return
			}
		}

		// Cache miss - need to get certificate
		if platform != nil {
			// Platform known - perform cert selection
			cert, tcbm, err := selectPCKCert(db, pcsClient, qeID, pceID, cpuSVN, pceSVN, platform)
			if err != nil {
				log.Printf("Certificate selection failed: %v", err)
				http.Error(w, "Failed to select certificate", http.StatusNotFound)
				return
			}

			// Store the TCB mapping
			db.PutPlatformTCB(qeID, pceID, cpuSVN, pceSVN, tcbm)

			writePCKCertResponse(w, cert, tcbm, platform, db)
		} else {
			// Platform unknown - fetch from Intel PCS (LAZY mode)
			if cacheMode != "LAZY" {
				http.Error(w, "Platform unknown", http.StatusNotFound)
				return
			}

			if err := fetchAndCachePlatform(db, pcsClient, qeID, pceID, encPPID); err != nil {
				log.Printf("Failed to fetch platform from PCS: %v", err)
				http.Error(w, "Platform not found", http.StatusNotFound)
				return
			}

			// Try again after caching
			platform, _ = db.GetPlatform(qeID, pceID)
			if platform == nil {
				http.Error(w, "Failed to cache platform", http.StatusInternalServerError)
				return
			}

			cert, tcbm, err := selectPCKCert(db, pcsClient, qeID, pceID, cpuSVN, pceSVN, platform)
			if err != nil {
				http.Error(w, "Failed to select certificate", http.StatusNotFound)
				return
			}

			db.PutPlatformTCB(qeID, pceID, cpuSVN, pceSVN, tcbm)
			writePCKCertResponse(w, cert, tcbm, platform, db)
		}
	}
}

// selectPCKCert performs PCK certificate selection
func selectPCKCert(db *cache.DB, pcsClient *pcs.Client, qeID, pceID, cpuSVN, pceSVN string, platform *cache.Platform) ([]byte, string, error) {
	// Get all certs for this platform
	allCerts, err := db.GetAllCerts(qeID, pceID)
	if err != nil || len(allCerts) == 0 {
		return nil, "", fmt.Errorf("no certificates found for platform")
	}

	// Get TCB info for selection
	tcbInfo, err := db.GetTCBInfo(cache.ProdTypeSGX, platform.FMSPC, "4", cache.UpdateTypeEarly)
	if err != nil || tcbInfo == nil {
		tcbInfo, err = db.GetTCBInfo(cache.ProdTypeSGX, platform.FMSPC, "4", cache.UpdateTypeStandard)
	}
	if err != nil || tcbInfo == nil {
		return nil, "", fmt.Errorf("no TCB info found for FMSPC %s", platform.FMSPC)
	}

	// Convert certs map to slice for selection
	certList := make([]string, 0, len(allCerts))
	tcbmList := make([]string, 0, len(allCerts))
	for tcbm, cert := range allCerts {
		certList = append(certList, string(cert))
		tcbmList = append(tcbmList, tcbm)
	}

	// Select best matching certificate
	idx, err := pckcertselect.SelectCertificate(certList, cpuSVN, pceSVN, pceID, tcbInfo)
	if err != nil || idx < 0 {
		return nil, "", fmt.Errorf("no matching certificate found")
	}

	return []byte(certList[idx]), tcbmList[idx], nil
}

// fetchAndCachePlatform fetches platform data from Intel PCS and caches it
func fetchAndCachePlatform(db *cache.DB, pcsClient *pcs.Client, qeID, pceID, encPPID string) error {
	// Fetch all PCK certs for this platform
	resp, err := pcsClient.GetPCKCerts(encPPID, pceID)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("PCS returned status %d", resp.StatusCode)
	}

	// Extract headers
	fmspc := resp.Headers.Get("SGX-FMSPC")
	caType := resp.Headers.Get("SGX-PCK-Certificate-CA-Type")
	issuerChain := resp.Headers.Get("SGX-PCK-Certificate-Issuer-Chain")

	if fmspc == "" || caType == "" {
		return fmt.Errorf("missing required headers from PCS")
	}

	// Parse response to extract individual certificates
	// The response contains TCB info embedded in the JSON
	var certsData map[string]interface{}
	if err := json.Unmarshal(resp.Body, &certsData); err != nil {
		return err
	}

	// Store platform
	platform := &cache.Platform{
		QEID:    qeID,
		PCEID:   pceID,
		EncPPID: encPPID,
		FMSPC:   fmspc,
		CA:      strings.ToLower(caType),
	}
	if err := db.PutPlatform(qeID, pceID, platform); err != nil {
		return err
	}

	// Store certificate chain
	if issuerChain != "" {
		// Parse and store cert chain (simplified)
		certChain := &cache.CertChain{
			CA:        strings.ToLower(caType),
			RootCert:  issuerChain, // In reality, need to parse this
			IntmdCert: "",
		}
		db.PutCertChain(strings.ToLower(caType), certChain)
	}

	// Store individual certificates from the response
	// This is simplified - actual implementation needs to parse the certs array
	if certs, ok := certsData["certs"].([]interface{}); ok {
		for _, certData := range certs {
			if certMap, ok := certData.(map[string]interface{}); ok {
				if tcbm, ok := certMap["tcbm"].(string); ok {
					if cert, ok := certMap["cert"].(string); ok {
						db.PutCert(qeID, pceID, tcbm, []byte(cert))
					}
				}
			}
		}
	}

	return nil
}

// writePCKCertResponse writes a PCK certificate response
func writePCKCertResponse(w http.ResponseWriter, cert []byte, tcbm string, platform *cache.Platform, db *cache.DB) {
	// Get cert chain
	certChain, _ := db.GetCertChain(platform.CA)
	issuerChain := ""
	if certChain != nil {
		issuerChain = certChain.RootCert + certChain.IntmdCert
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("SGX-TCBm", tcbm)
	w.Header().Set("SGX-FMSPC", platform.FMSPC)
	w.Header().Set("SGX-PCK-Certificate-CA-Type", platform.CA)
	if issuerChain != "" {
		w.Header().Set("SGX-PCK-Certificate-Issuer-Chain", issuerChain)
	}
	w.WriteHeader(http.StatusOK)
	w.Write(cert)
}

// handleTCB handles TCB info requests
func handleTCB(db *cache.DB, pcsClient *pcs.Client, prodType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmspc := strings.ToUpper(r.URL.Query().Get("fmspc"))
		update := strings.ToLower(r.URL.Query().Get("update"))
		version := extractAPIVersion(r.URL.Path)

		if fmspc == "" {
			http.Error(w, "Missing fmspc parameter", http.StatusBadRequest)
			return
		}

		if update == "" {
			update = cache.UpdateTypeStandard
		}

		// Try cache first
		tcbInfo, err := db.GetTCBInfo(prodType, fmspc, version, update)
		if err == nil && tcbInfo != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(tcbInfo)
			return
		}

		// Cache miss - fetch from PCS
		var resp *pcs.Response
		if prodType == "tdx" {
			resp, err = pcsClient.GetTCBInfoForTDX(fmspc, version, update)
		} else {
			resp, err = pcsClient.GetTCBInfoForSGX(fmspc, version, update)
		}

		if err != nil {
			log.Printf("Failed to fetch TCB info: %v", err)
			http.Error(w, "Failed to fetch TCB info", http.StatusNotFound)
			return
		}

		if resp.StatusCode != 200 {
			http.Error(w, fmt.Sprintf("PCS returned status %d", resp.StatusCode), resp.StatusCode)
			return
		}

		// Cache the result
		db.PutTCBInfo(prodType, fmspc, version, update, resp.Body)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(resp.Body)
	}
}

// handleIdentity handles enclave identity requests
func handleIdentity(db *cache.DB, pcsClient *pcs.Client, identityID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		update := strings.ToLower(r.URL.Query().Get("update"))
		version := extractAPIVersion(r.URL.Path)

		if update == "" {
			update = cache.UpdateTypeStandard
		}

		// Try cache first
		identity, err := db.GetIdentity(identityID, version, update)
		if err == nil && identity != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(identity)
			return
		}

		// Cache miss - fetch from PCS
		resp, err := pcsClient.GetEnclaveIdentity(identityID, version, update)
		if err != nil {
			log.Printf("Failed to fetch enclave identity: %v", err)
			http.Error(w, "Failed to fetch identity", http.StatusNotFound)
			return
		}

		if resp.StatusCode != 200 {
			http.Error(w, fmt.Sprintf("PCS returned status %d", resp.StatusCode), resp.StatusCode)
			return
		}

		// Cache the result
		db.PutIdentity(identityID, version, update, resp.Body)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(resp.Body)
	}
}

// handlePCKCRL handles PCK CRL requests
func handlePCKCRL(db *cache.DB, pcsClient *pcs.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ca := strings.ToLower(r.URL.Query().Get("ca"))
		if ca == "" {
			http.Error(w, "Missing ca parameter", http.StatusBadRequest)
			return
		}

		// Try cache first
		crl, err := db.GetCRL(ca)
		if err == nil && crl != nil {
			w.Header().Set("Content-Type", "application/pkix-crl")
			w.WriteHeader(http.StatusOK)
			w.Write(crl)
			return
		}

		// Cache miss - fetch from PCS
		resp, err := pcsClient.GetPCKCRL(ca)
		if err != nil {
			log.Printf("Failed to fetch PCK CRL: %v", err)
			http.Error(w, "Failed to fetch CRL", http.StatusNotFound)
			return
		}

		if resp.StatusCode != 200 {
			http.Error(w, fmt.Sprintf("PCS returned status %d", resp.StatusCode), resp.StatusCode)
			return
		}

		// Cache the result
		db.PutCRL(ca, resp.Body)

		w.Header().Set("Content-Type", "application/pkix-crl")
		w.WriteHeader(http.StatusOK)
		w.Write(resp.Body)
	}
}

// handleRootCACRL handles root CA CRL requests
func handleRootCACRL(db *cache.DB, pcsClient *pcs.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rootca := strings.ToLower(r.URL.Query().Get("rootca"))
		if rootca == "" {
			http.Error(w, "Missing rootca parameter", http.StatusBadRequest)
			return
		}

		// Try cache first
		crl, err := db.GetRootCACRL(rootca)
		if err == nil && crl != nil {
			w.Header().Set("Content-Type", "application/pkix-crl")
			w.WriteHeader(http.StatusOK)
			w.Write(crl)
			return
		}

		// Cache miss - fetch from PCS
		resp, err := pcsClient.GetRootCACRL(rootca)
		if err != nil {
			log.Printf("Failed to fetch root CA CRL: %v", err)
			http.Error(w, "Failed to fetch CRL", http.StatusNotFound)
			return
		}

		if resp.StatusCode != 200 {
			http.Error(w, fmt.Sprintf("PCS returned status %d", resp.StatusCode), resp.StatusCode)
			return
		}

		// Cache the result
		db.PutRootCACRL(rootca, resp.Body)

		w.Header().Set("Content-Type", "application/pkix-crl")
		w.WriteHeader(http.StatusOK)
		w.Write(resp.Body)
	}
}

// handleGenericCRL handles generic CRL requests by URI
func handleGenericCRL(db *cache.DB, pcsClient *pcs.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uri := r.URL.Query().Get("uri")
		if uri == "" {
			http.Error(w, "Missing uri parameter", http.StatusBadRequest)
			return
		}

		// Try cache first
		crl, err := db.GetCRLByURI(uri)
		if err == nil && crl != nil {
			w.Header().Set("Content-Type", "application/pkix-crl")
			w.WriteHeader(http.StatusOK)
			w.Write(crl)
			return
		}

		// Cache miss - fetch from URL
		resp, err := pcsClient.GetCRL(uri)
		if err != nil {
			log.Printf("Failed to fetch CRL from URI: %v", err)
			http.Error(w, "Failed to fetch CRL", http.StatusNotFound)
			return
		}

		if resp.StatusCode != 200 {
			http.Error(w, fmt.Sprintf("Failed to fetch CRL (status %d)", resp.StatusCode), resp.StatusCode)
			return
		}

		// Cache the result
		db.PutCRLByURI(uri, resp.Body)

		w.Header().Set("Content-Type", "application/pkix-crl")
		w.WriteHeader(http.StatusOK)
		w.Write(resp.Body)
	}
}

// Stub handlers for platform registration and admin endpoints
func handleRegisterPlatforms(db *cache.DB, pcsClient *pcs.Client, cacheMode string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO: Implement platform registration
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}
}

func handleGetPlatforms(db *cache.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO: Implement get platforms
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("[]"))
	}
}

func handlePlatformCollateral(db *cache.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO: Implement platform collateral upload
		w.WriteHeader(http.StatusOK)
	}
}

func handleRefresh(db *cache.DB, pcsClient *pcs.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO: Trigger manual refresh
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Refresh triggered"))
	}
}

// addLogging adds request logging middleware
func addLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
