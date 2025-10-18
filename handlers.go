package main

import (
	"encoding/json"
	"fmt"
	"io"
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
	mux.HandleFunc("PUT /sgx/certification/v4/appraisalpolicy", auth.validateAdmin(handlePutAppraisalPolicy(db)))
	mux.HandleFunc("GET /sgx/certification/v4/appraisalpolicy", handleGetAppraisalPolicy(db))

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
	mux.HandleFunc("PUT /sgx/certification/v3/appraisalpolicy", auth.validateAdmin(handlePutAppraisalPolicy(db)))
	mux.HandleFunc("GET /sgx/certification/v3/appraisalpolicy", handleGetAppraisalPolicy(db))

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

	// Parse response - Intel PCS returns a JSON array of cert objects
	// Each object has "tcbm" and "cert" fields
	var certsArray []struct {
		TCBM string `json:"tcbm"`
		Cert string `json:"cert"`
	}
	if err := json.Unmarshal(resp.Body, &certsArray); err != nil {
		return err
	}

	// Filter out "Not available" certificates
	validCerts := 0
	for _, certData := range certsArray {
		if certData.Cert != "Not available" {
			validCerts++
		}
	}

	if validCerts == 0 {
		return fmt.Errorf("no valid certificates in PCS response")
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
		certChain := &cache.CertChain{
			CA:        strings.ToLower(caType),
			RootCert:  issuerChain,
			IntmdCert: "",
		}
		db.PutCertChain(strings.ToLower(caType), certChain)
	}

	// Store individual certificates from the response
	for _, certData := range certsArray {
		// Skip "Not available" certificates
		if certData.Cert == "Not available" {
			continue
		}
		db.PutCert(qeID, pceID, certData.TCBM, []byte(certData.Cert))
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

// PlatformRegistration represents a platform registration request
type PlatformRegistration struct {
	QEID             string `json:"qe_id"`
	PCEID            string `json:"pce_id"`
	CPUSVN           string `json:"cpu_svn"`
	PCESVN           string `json:"pce_svn"`
	EncPPID          string `json:"enc_ppid"`
	PlatformManifest string `json:"platform_manifest"`
}

// Stub handlers for platform registration and admin endpoints
func handleRegisterPlatforms(db *cache.DB, pcsClient *pcs.Client, cacheMode string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var platforms []PlatformRegistration
		if err := json.NewDecoder(r.Body).Decode(&platforms); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		updateType := r.URL.Query().Get("update")
		if updateType == "" {
			updateType = "standard"
		}
		updateType = strings.ToLower(updateType)
		if updateType != "standard" && updateType != "early" && updateType != "all" {
			http.Error(w, "Invalid update type", http.StatusBadRequest)
			return
		}

		// Process each platform registration
		// In LAZY mode, we fetch and cache certificates immediately
		// This is simpler than the Intel REQ mode which queues platforms
		for _, plat := range platforms {
			qeID := strings.ToUpper(plat.QEID)
			pceID := strings.ToUpper(plat.PCEID)
			encPPID := strings.ToUpper(plat.EncPPID)

			// Check if platform already exists
			existing, _ := db.GetPlatform(qeID, pceID)
			if existing != nil {
				// Platform already registered
				continue
			}

			// Fetch and cache platform data from Intel PCS
			if err := fetchAndCachePlatform(db, pcsClient, qeID, pceID, encPPID); err != nil {
				log.Printf("Failed to register platform %s/%s: %v", qeID, pceID, err)
				// Continue with next platform instead of failing entire request
				continue
			}
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}
}

func handleGetPlatforms(db *cache.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		source := r.URL.Query().Get("source")

		var platforms []*cache.Platform
		var err error

		if source == "" || source == "reg" || source == "reg_na" {
			// These modes are for platforms pending registration
			// In our simplified implementation, we auto-register platforms
			// So we return empty array for compatibility
			platforms = []*cache.Platform{}
		} else if len(source) >= 2 && source[0] == '[' && source[len(source)-1] == ']' {
			// Source is FMSPC array like "[FMSPC1,FMSPC2]"
			fmspcStr := source[1 : len(source)-1]
			var fmspcs []string
			if fmspcStr != "" {
				fmspcs = strings.Split(fmspcStr, ",")
			}
			platforms, err = db.GetPlatformsByFMSPC(fmspcs)
			if err != nil {
				http.Error(w, "Failed to retrieve platforms", http.StatusInternalServerError)
				return
			}
		} else {
			http.Error(w, "Invalid source parameter", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("platform-count", fmt.Sprintf("%d", len(platforms)))
		w.WriteHeader(http.StatusOK)

		if err := json.NewEncoder(w).Encode(platforms); err != nil {
			log.Printf("Failed to encode platforms: %v", err)
		}
	}
}

func handlePlatformCollateral(db *cache.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Platform collateral upload for OFFLINE mode
		// This is a complex endpoint that accepts TCB info, certs, CRLs, etc.
		// For now, return a not implemented status
		http.Error(w, "Platform collateral upload not yet implemented", http.StatusNotImplemented)
	}
}

func handlePutAppraisalPolicy(db *cache.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Read policy data from request body
		policyData, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}

		// Parse policy JSON to extract FMSPC
		var policyObj map[string]interface{}
		if err := json.Unmarshal(policyData, &policyObj); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Extract FMSPC from policy
		fmspc, ok := policyObj["fmspc"].(string)
		if !ok || fmspc == "" {
			http.Error(w, "Missing or invalid fmspc in policy", http.StatusBadRequest)
			return
		}

		// Store policy
		if err := db.PutAppraisalPolicy(fmspc, policyData); err != nil {
			log.Printf("Failed to store appraisal policy: %v", err)
			http.Error(w, "Failed to store policy", http.StatusInternalServerError)
			return
		}

		// Return policy ID (using FMSPC as ID)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmspc))
	}
}

func handleGetAppraisalPolicy(db *cache.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmspc := r.URL.Query().Get("fmspc")
		if fmspc == "" || len(fmspc) != 12 {
			http.Error(w, "Invalid fmspc parameter", http.StatusBadRequest)
			return
		}

		policy, err := db.GetAppraisalPolicy(strings.ToUpper(fmspc))
		if err != nil {
			log.Printf("Failed to retrieve appraisal policy: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if policy == nil {
			http.Error(w, "No policy found for this FMSPC", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(policy)
	}
}

func handleRefresh(db *cache.DB, pcsClient *pcs.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		refreshType := r.URL.Query().Get("type")
		fmspc := r.URL.Query().Get("fmspc")

		// Validate type parameter
		if refreshType != "" && refreshType != "certs" {
			http.Error(w, "Invalid refresh type", http.StatusBadRequest)
			return
		}

		// Start refresh in background
		go func() {
			if refreshType == "certs" {
				// Refresh PCK certs for specific FMSPC
				if fmspc == "" {
					log.Println("Refresh type 'certs' requires fmspc parameter")
					return
				}
				refreshPCKCertsForFMSPC(db, pcsClient, strings.ToUpper(fmspc))
			} else {
				// Refresh all collateral
				refreshAllCollateral(db, pcsClient)
			}
		}()

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Refresh triggered"))
	}
}

// refreshAllCollateral refreshes all cached collateral (CRLs, TCBs, identities)
func refreshAllCollateral(db *cache.DB, pcsClient *pcs.Client) {
	log.Println("Manual refresh triggered for all collateral")

	// Refresh TCB info for all known FMSPCs
	fmspcs := db.GetAllFMSPCs()
	for _, fmspc := range fmspcs {
		for _, version := range []string{"3", "4"} {
			for _, updateType := range []string{cache.UpdateTypeStandard, cache.UpdateTypeEarly} {
				resp, err := pcsClient.GetTCBInfoForSGX(fmspc, version, updateType)
				if err != nil {
					log.Printf("Failed to refresh TCB info for FMSPC %s (v%s/%s): %v", fmspc, version, updateType, err)
					continue
				}
				if resp.StatusCode == 200 {
					if err := db.PutTCBInfo(cache.ProdTypeSGX, fmspc, version, updateType, resp.Body); err != nil {
						log.Printf("Failed to store TCB info: %v", err)
					}
				}
			}
		}
	}

	// Refresh enclave identities
	identities := []string{cache.IdentityQE, cache.IdentityQVE, cache.IdentityTDQE}
	for _, version := range []string{"3", "4"} {
		for _, id := range identities {
			for _, updateType := range []string{cache.UpdateTypeStandard, cache.UpdateTypeEarly} {
				resp, err := pcsClient.GetEnclaveIdentity(id, version, updateType)
				if err != nil {
					continue
				}
				if resp.StatusCode == 200 {
					db.PutIdentity(id, version, updateType, resp.Body)
				}
			}
		}
	}

	// Refresh CRLs
	for _, ca := range []string{cache.CAProcessor, cache.CAPlatform} {
		resp, err := pcsClient.GetPCKCRL(ca)
		if err != nil {
			continue
		}
		if resp.StatusCode == 200 {
			db.PutCRL(ca, resp.Body)
		}
	}

	log.Println("Manual refresh complete")
}

// refreshPCKCertsForFMSPC refreshes PCK certificates for a specific FMSPC
func refreshPCKCertsForFMSPC(db *cache.DB, pcsClient *pcs.Client, fmspc string) {
	log.Printf("Manual refresh triggered for PCK certs with FMSPC %s", fmspc)
	// This would require fetching all platforms with this FMSPC and re-fetching their certs
	// For now, log that it's not fully implemented
	log.Println("PCK cert refresh for specific FMSPC not yet implemented")
}

// addLogging adds request logging middleware
func addLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
