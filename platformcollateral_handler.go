package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/url"
	"strings"

	"github.com/KarpelesLab/intel-dcapd/cache"
	"github.com/KarpelesLab/intel-dcapd/pckcertselect"
	"github.com/cockroachdb/pebble"
)

// toUpper converts a string to uppercase, handling nil/empty strings
func toUpper(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s)
}

// extractFMSPCAndCA parses a PCK certificate to extract FMSPC and CA
func extractFMSPCAndCA(certPEM string) (fmspc string, ca string, err error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", "", fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Extract SGX extensions
	const sgxExtensionOID = "1.2.840.113741.1.13.1"

	for _, ext := range cert.Extensions {
		if ext.Id.String() == sgxExtensionOID {
			// Parse the SGX extension to extract FMSPC
			fmspcBytes, caStr, err := pckcertselect.ParseSGXExtensions(ext.Value)
			if err != nil {
				return "", "", fmt.Errorf("failed to parse SGX extensions: %w", err)
			}
			fmspc = strings.ToUpper(hex.EncodeToString(fmspcBytes))
			ca = caStr
			return fmspc, ca, nil
		}
	}

	return "", "", fmt.Errorf("SGX extension not found in certificate")
}

// PlatformTCB represents a platform TCB configuration
type PlatformTCB struct {
	CPUSVN string
	PCESVN string
}

// getAllPlatformTCBs retrieves all cached TCB configurations for a platform
func getAllPlatformTCBs(db *cache.DB, qeID, pceID string) ([]PlatformTCB, error) {
	// Scan all platform_tcb entries for this platform
	prefix := fmt.Sprintf("platform_tcb:%s:%s:", qeID, pceID)
	iter, err := db.NewIter(&pebble.IterOptions{
		LowerBound: []byte(prefix),
		UpperBound: []byte(prefix + "\xff"),
	})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var tcbs []PlatformTCB
	seen := make(map[string]bool)

	for iter.First(); iter.Valid(); iter.Next() {
		key := string(iter.Key())
		// Key format: platform_tcb:qeid:pceid:cpusvn:pcesvn
		parts := strings.Split(key, ":")
		if len(parts) == 5 {
			cpusvn := parts[3]
			pcesvn := parts[4]
			tcbKey := cpusvn + ":" + pcesvn
			if !seen[tcbKey] {
				tcbs = append(tcbs, PlatformTCB{
					CPUSVN: cpusvn,
					PCESVN: pcesvn,
				})
				seen[tcbKey] = true
			}
		}
	}

	return tcbs, nil
}

// processPckCerts processes PCK certificates from the collateral and stores them using batch
// This matches Intel's processPckCerts function in platformCollateralService.js
func processPckCerts(db *cache.DB, batch *pebble.Batch, platforms []PlatformEntry, pckCerts []PCKCerts, tcbInfos []TCBInfoEntry, version int) error {
	for _, pckEntry := range pckCerts {
		qeID := toUpper(pckEntry.QEID)
		pceID := toUpper(pckEntry.PCEID)

		logVerbose("Processing PCK certs for platform qe_id=%s pce_id=%s (%d certs)", qeID, pceID, len(pckEntry.Certs))

		if len(pckEntry.Certs) == 0 {
			return fmt.Errorf("PCK certificates not found in the collateral file for qe_id=%s pce_id=%s", qeID, pceID)
		}

		// Decode all certificates first
		type DecodedCert struct {
			TCBM string
			Cert string
		}
		decodedCerts := make([]DecodedCert, 0, len(pckEntry.Certs))

		for _, cert := range pckEntry.Certs {
			tcbm := toUpper(cert.TCBM)
			certPEM, err := url.QueryUnescape(cert.Cert)
			if err != nil {
				return fmt.Errorf("failed to decode certificate for qe_id=%s pce_id=%s tcbm=%s: %w", qeID, pceID, tcbm, err)
			}
			decodedCerts = append(decodedCerts, DecodedCert{
				TCBM: tcbm,
				Cert: certPEM,
			})
		}

		// Parse first certificate to get FMSPC and CA
		fmspc, ca, err := extractFMSPCAndCA(decodedCerts[0].Cert)
		if err != nil {
			return fmt.Errorf("failed to extract FMSPC and CA from certificate: %w", err)
		}

		logVerbose("  Extracted FMSPC=%s CA=%s from certificate", fmspc, ca)

		// Find TCB info for this FMSPC
		var tcbInfoJSON []byte
		for _, tcbInfo := range tcbInfos {
			if toUpper(tcbInfo.FMSPC) == fmspc {
				// Select appropriate TCB info based on version
				if version < 4 {
					if len(tcbInfo.TCBInfoEarly) > 0 {
						tcbInfoJSON = tcbInfo.TCBInfoEarly
					} else if len(tcbInfo.TCBInfo) > 0 {
						tcbInfoJSON = tcbInfo.TCBInfo
					}
				} else {
					if len(tcbInfo.SGXTCBInfoEarly) > 0 {
						tcbInfoJSON = tcbInfo.SGXTCBInfoEarly
					} else if len(tcbInfo.SGXTCBInfo) > 0 {
						tcbInfoJSON = tcbInfo.SGXTCBInfo
					}
				}
				break
			}
		}

		if len(tcbInfoJSON) == 0 {
			return fmt.Errorf("can't find TCB info for FMSPC %s", fmspc)
		}

		// Get cached platform TCBs (before deleting certs)
		cachedTCBs, err := getAllPlatformTCBs(db, qeID, pceID)
		if err != nil {
			return fmt.Errorf("failed to get cached platform TCBs: %w", err)
		}

		// Get new platforms from the upload
		var newPlatforms []PlatformEntry
		for _, p := range platforms {
			if toUpper(p.QEID) == qeID && toUpper(p.PCEID) == pceID {
				newPlatforms = append(newPlatforms, p)
			}
		}

		// Merge cached and new TCBs (avoiding duplicates)
		allTCBs := make(map[string]PlatformTCB)
		for _, tcb := range cachedTCBs {
			key := toUpper(tcb.CPUSVN) + ":" + toUpper(tcb.PCESVN)
			allTCBs[key] = PlatformTCB{CPUSVN: toUpper(tcb.CPUSVN), PCESVN: toUpper(tcb.PCESVN)}
		}
		for _, p := range newPlatforms {
			if p.CPUSVN != "" && p.PCESVN != "" {
				key := toUpper(p.CPUSVN) + ":" + toUpper(p.PCESVN)
				allTCBs[key] = PlatformTCB{CPUSVN: toUpper(p.CPUSVN), PCESVN: toUpper(p.PCESVN)}
			}
		}

		logVerbose("  Total TCBs to process: %d (cached: %d, new: %d)", len(allTCBs), len(cachedTCBs), len(newPlatforms))

		// Delete existing certificates for this platform (flush and add)
		certPrefix := fmt.Sprintf("cert:%s:%s:", qeID, pceID)
		iter, err := db.NewIter(&pebble.IterOptions{
			LowerBound: []byte(certPrefix),
			UpperBound: []byte(certPrefix + "\xff"),
		})
		if err != nil {
			return err
		}
		for iter.First(); iter.Valid(); iter.Next() {
			if err := batch.Delete(iter.Key(), pebble.Sync); err != nil {
				iter.Close()
				return err
			}
		}
		iter.Close()

		// Store new certificates
		for _, decoded := range decodedCerts {
			certKey := fmt.Sprintf("cert:%s:%s:%s", qeID, pceID, decoded.TCBM)
			if err := batch.Set([]byte(certKey), []byte(decoded.Cert), pebble.Sync); err != nil {
				return fmt.Errorf("failed to store certificate: %w", err)
			}
		}

		logVerbose("  Stored %d certificates", len(decodedCerts))

		// Run certificate selection for each TCB configuration
		for _, tcb := range allTCBs {
			// Prepare cert list for selection
			certList := make([]string, len(decodedCerts))
			for i, dc := range decodedCerts {
				certList[i] = dc.Cert
			}

			// Run PCK cert selection
			idx, err := pckcertselect.SelectCertificate(certList, tcb.CPUSVN, tcb.PCESVN, pceID, tcbInfoJSON)
			if err != nil || idx < 0 {
				log.Printf("Warning: certificate selection failed for qe_id=%s pce_id=%s cpu_svn=%s pce_svn=%s: %v",
					qeID, pceID, tcb.CPUSVN, tcb.PCESVN, err)
				continue
			}

			selectedTCBM := decodedCerts[idx].TCBM

			// Store platform_tcb mapping
			tcbKey := fmt.Sprintf("platform_tcb:%s:%s:%s:%s", qeID, pceID, tcb.CPUSVN, tcb.PCESVN)
			if err := batch.Set([]byte(tcbKey), []byte(selectedTCBM), pebble.Sync); err != nil {
				return fmt.Errorf("failed to store platform_tcb mapping: %w", err)
			}

			logVerbose("  Selected certificate for cpu_svn=%s pce_svn=%s -> tcbm=%s",
				tcb.CPUSVN, tcb.PCESVN, selectedTCBM)
		}

		// Update platforms table (for new platforms only)
		for _, p := range newPlatforms {
			platform := &cache.Platform{
				QEID:             qeID,
				PCEID:            pceID,
				EncPPID:          toUpper(p.EncPPID),
				PlatformManifest: toUpper(p.PlatformManifest),
				FMSPC:            fmspc,
				CA:               ca,
			}

			platformKey := fmt.Sprintf("platform:%s:%s", qeID, pceID)
			platformJSON, err := json.Marshal(platform)
			if err != nil {
				return fmt.Errorf("failed to marshal platform: %w", err)
			}
			if err := batch.Set([]byte(platformKey), platformJSON, pebble.Sync); err != nil {
				return fmt.Errorf("failed to store platform: %w", err)
			}
		}

		logVerbose("  Updated platform record with FMSPC and CA")
	}

	return nil
}

// processTcbInfo processes TCB information from the collateral and stores it using batch
func processTcbInfo(batch *pebble.Batch, tcbInfos []TCBInfoEntry, version int) error {
	for _, tcbEntry := range tcbInfos {
		fmspc := toUpper(tcbEntry.FMSPC)
		logVerbose("Processing TCB info for fmspc=%s", fmspc)

		// Store v3 TCB info (standard)
		if len(tcbEntry.TCBInfo) > 0 {
			key := fmt.Sprintf("tcb:sgx:%s:standard", fmspc)
			if err := batch.Set([]byte(key), tcbEntry.TCBInfo, pebble.Sync); err != nil {
				return fmt.Errorf("failed to store v3 tcbinfo: %w", err)
			}
			logVerbose("  Stored v3 standard TCB info (%d bytes)", len(tcbEntry.TCBInfo))
		}

		// Store v3 TCB info (early)
		if len(tcbEntry.TCBInfoEarly) > 0 {
			key := fmt.Sprintf("tcb:sgx:%s:early", fmspc)
			if err := batch.Set([]byte(key), tcbEntry.TCBInfoEarly, pebble.Sync); err != nil {
				return fmt.Errorf("failed to store v3 tcbinfo_early: %w", err)
			}
			logVerbose("  Stored v3 early TCB info (%d bytes)", len(tcbEntry.TCBInfoEarly))
		}

		// Store v4 SGX TCB info (standard)
		if len(tcbEntry.SGXTCBInfo) > 0 {
			key := fmt.Sprintf("tcb:sgx:%s:v4:standard", fmspc)
			if err := batch.Set([]byte(key), tcbEntry.SGXTCBInfo, pebble.Sync); err != nil {
				return fmt.Errorf("failed to store v4 sgx_tcbinfo: %w", err)
			}
			logVerbose("  Stored v4 SGX standard TCB info (%d bytes)", len(tcbEntry.SGXTCBInfo))
		}

		// Store v4 SGX TCB info (early)
		if len(tcbEntry.SGXTCBInfoEarly) > 0 {
			key := fmt.Sprintf("tcb:sgx:%s:v4:early", fmspc)
			if err := batch.Set([]byte(key), tcbEntry.SGXTCBInfoEarly, pebble.Sync); err != nil {
				return fmt.Errorf("failed to store v4 sgx_tcbinfo_early: %w", err)
			}
			logVerbose("  Stored v4 SGX early TCB info (%d bytes)", len(tcbEntry.SGXTCBInfoEarly))
		}

		// Store v4 TDX TCB info (standard)
		if len(tcbEntry.TDXTCBInfo) > 0 {
			key := fmt.Sprintf("tcb:tdx:%s:v4:standard", fmspc)
			if err := batch.Set([]byte(key), tcbEntry.TDXTCBInfo, pebble.Sync); err != nil {
				return fmt.Errorf("failed to store v4 tdx_tcbinfo: %w", err)
			}
			logVerbose("  Stored v4 TDX standard TCB info (%d bytes)", len(tcbEntry.TDXTCBInfo))
		}

		// Store v4 TDX TCB info (early)
		if len(tcbEntry.TDXTCBInfoEarly) > 0 {
			key := fmt.Sprintf("tcb:tdx:%s:v4:early", fmspc)
			if err := batch.Set([]byte(key), tcbEntry.TDXTCBInfoEarly, pebble.Sync); err != nil {
				return fmt.Errorf("failed to store v4 tdx_tcbinfo_early: %w", err)
			}
			logVerbose("  Stored v4 TDX early TCB info (%d bytes)", len(tcbEntry.TDXTCBInfoEarly))
		}
	}

	return nil
}

// processCRLs processes CRL data from the collateral and stores it using batch
func processCRLs(batch *pebble.Batch, pckcacrl *PCKCaCrl, rootCaCrl, rootCaCrlCdp string) error {
	if pckcacrl != nil {
		// Store processor CRL
		if pckcacrl.ProcessorCrl != "" {
			crlData, err := hex.DecodeString(pckcacrl.ProcessorCrl)
			if err != nil {
				return fmt.Errorf("failed to decode processor CRL: %w", err)
			}
			key := "crl:processor"
			if err := batch.Set([]byte(key), crlData, pebble.Sync); err != nil {
				return fmt.Errorf("failed to store processor CRL: %w", err)
			}
			logVerbose("Stored processor CRL (%d bytes)", len(crlData))
		}

		// Store platform CRL
		if pckcacrl.PlatformCrl != "" {
			crlData, err := hex.DecodeString(pckcacrl.PlatformCrl)
			if err != nil {
				return fmt.Errorf("failed to decode platform CRL: %w", err)
			}
			key := "crl:platform"
			if err := batch.Set([]byte(key), crlData, pebble.Sync); err != nil {
				return fmt.Errorf("failed to store platform CRL: %w", err)
			}
			logVerbose("Stored platform CRL (%d bytes)", len(crlData))
		}
	}

	// Store root CA CRL
	if rootCaCrl != "" {
		crlData, err := hex.DecodeString(rootCaCrl)
		if err != nil {
			return fmt.Errorf("failed to decode root CA CRL: %w", err)
		}
		key := "crl:root:intel"
		if err := batch.Set([]byte(key), crlData, pebble.Sync); err != nil {
			return fmt.Errorf("failed to store root CA CRL: %w", err)
		}
		logVerbose("Stored root CA CRL (%d bytes)", len(crlData))

		// Also store CDP URL if provided
		if rootCaCrlCdp != "" {
			cdpKey := "crl:root:intel:cdp"
			if err := batch.Set([]byte(cdpKey), []byte(rootCaCrlCdp), pebble.Sync); err != nil {
				return fmt.Errorf("failed to store root CA CRL CDP: %w", err)
			}
			logVerbose("Stored root CA CRL CDP: %s", rootCaCrlCdp)
		}
	}

	return nil
}

// processIdentities processes enclave identities from the collateral and stores them using batch
func processIdentities(batch *pebble.Batch, collaterals *Collaterals) error {
	// QE Identity (standard)
	if len(collaterals.QEIdentity) > 0 {
		key := "identity:QE:standard"
		if err := batch.Set([]byte(key), collaterals.QEIdentity, pebble.Sync); err != nil {
			return fmt.Errorf("failed to store QE identity: %w", err)
		}
		logVerbose("Stored QE identity (standard) (%d bytes)", len(collaterals.QEIdentity))
	}

	// QE Identity (early)
	if len(collaterals.QEIdentityEarly) > 0 {
		key := "identity:QE:early"
		if err := batch.Set([]byte(key), collaterals.QEIdentityEarly, pebble.Sync); err != nil {
			return fmt.Errorf("failed to store QE identity early: %w", err)
		}
		logVerbose("Stored QE identity (early) (%d bytes)", len(collaterals.QEIdentityEarly))
	}

	// TDQE Identity (standard)
	if len(collaterals.TDQEIdentity) > 0 {
		key := "identity:TDQE:standard"
		if err := batch.Set([]byte(key), collaterals.TDQEIdentity, pebble.Sync); err != nil {
			return fmt.Errorf("failed to store TDQE identity: %w", err)
		}
		logVerbose("Stored TDQE identity (standard) (%d bytes)", len(collaterals.TDQEIdentity))
	}

	// TDQE Identity (early)
	if len(collaterals.TDQEIdentityEarly) > 0 {
		key := "identity:TDQE:early"
		if err := batch.Set([]byte(key), collaterals.TDQEIdentityEarly, pebble.Sync); err != nil {
			return fmt.Errorf("failed to store TDQE identity early: %w", err)
		}
		logVerbose("Stored TDQE identity (early) (%d bytes)", len(collaterals.TDQEIdentityEarly))
	}

	// QVE Identity (standard)
	if len(collaterals.QVEIdentity) > 0 {
		key := "identity:QVE:standard"
		if err := batch.Set([]byte(key), collaterals.QVEIdentity, pebble.Sync); err != nil {
			return fmt.Errorf("failed to store QVE identity: %w", err)
		}
		logVerbose("Stored QVE identity (standard) (%d bytes)", len(collaterals.QVEIdentity))
	}

	// QVE Identity (early)
	if len(collaterals.QVEIdentityEarly) > 0 {
		key := "identity:QVE:early"
		if err := batch.Set([]byte(key), collaterals.QVEIdentityEarly, pebble.Sync); err != nil {
			return fmt.Errorf("failed to store QVE identity early: %w", err)
		}
		logVerbose("Stored QVE identity (early) (%d bytes)", len(collaterals.QVEIdentityEarly))
	}

	return nil
}

// processCertificates processes certificate chains from the collateral and stores them using batch
// Returns the root certificate from each chain for validation
func processCertificates(batch *pebble.Batch, certs CertificatesEntry) ([]string, error) {
	var rootCerts []string

	// PCK Certificate Issuer Chain (processor and platform)
	if len(certs.PCKCertIssuerChain) > 0 {
		for caType, chain := range certs.PCKCertIssuerChain {
			// Decode URL-encoded chain
			chainDecoded, err := url.QueryUnescape(chain)
			if err != nil {
				return nil, fmt.Errorf("failed to decode PCK cert issuer chain for %s: %w", caType, err)
			}

			// Extract root cert from chain
			rootCert := extractRootCert(chainDecoded)
			if rootCert != "" {
				rootCerts = append(rootCerts, rootCert)
			}

			key := fmt.Sprintf("certchain:pck:%s", caType)
			if err := batch.Set([]byte(key), []byte(chainDecoded), pebble.Sync); err != nil {
				return nil, fmt.Errorf("failed to store PCK cert issuer chain for %s: %w", caType, err)
			}
			logVerbose("Stored PCK cert issuer chain for %s (%d bytes)", caType, len(chainDecoded))
		}
	}

	// TCB Info Issuer Chain (v3)
	if certs.TCBInfoIssuerChain != "" {
		chainDecoded, err := url.QueryUnescape(certs.TCBInfoIssuerChain)
		if err != nil {
			return nil, fmt.Errorf("failed to decode TCB info issuer chain: %w", err)
		}

		rootCert := extractRootCert(chainDecoded)
		if rootCert != "" {
			rootCerts = append(rootCerts, rootCert)
		}

		key := "certchain:tcbinfo:v3"
		if err := batch.Set([]byte(key), []byte(chainDecoded), pebble.Sync); err != nil {
			return nil, fmt.Errorf("failed to store TCB info issuer chain: %w", err)
		}
		logVerbose("Stored TCB info issuer chain v3 (%d bytes)", len(chainDecoded))
	}

	// TCB Info Issuer Chain (v4)
	if certs.TCBInfoIssuerChainV4 != "" {
		chainDecoded, err := url.QueryUnescape(certs.TCBInfoIssuerChainV4)
		if err != nil {
			return nil, fmt.Errorf("failed to decode TCB info issuer chain v4: %w", err)
		}

		rootCert := extractRootCert(chainDecoded)
		if rootCert != "" {
			rootCerts = append(rootCerts, rootCert)
		}

		key := "certchain:tcbinfo:v4"
		if err := batch.Set([]byte(key), []byte(chainDecoded), pebble.Sync); err != nil {
			return nil, fmt.Errorf("failed to store TCB info issuer chain v4: %w", err)
		}
		logVerbose("Stored TCB info issuer chain v4 (%d bytes)", len(chainDecoded))
	}

	// Enclave Identity Issuer Chain
	if certs.EnclaveIdentityIssuerChain != "" {
		chainDecoded, err := url.QueryUnescape(certs.EnclaveIdentityIssuerChain)
		if err != nil {
			return nil, fmt.Errorf("failed to decode enclave identity issuer chain: %w", err)
		}

		rootCert := extractRootCert(chainDecoded)
		if rootCert != "" {
			rootCerts = append(rootCerts, rootCert)
		}

		key := "certchain:identity"
		if err := batch.Set([]byte(key), []byte(chainDecoded), pebble.Sync); err != nil {
			return nil, fmt.Errorf("failed to store enclave identity issuer chain: %w", err)
		}
		logVerbose("Stored enclave identity issuer chain (%d bytes)", len(chainDecoded))
	}

	return rootCerts, nil
}

// extractRootCert extracts the root certificate from a PEM chain
func extractRootCert(pemChain string) string {
	var lastCert string
	rest := []byte(pemChain)

	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			lastCert = string(pem.EncodeToMemory(block))
		}
		rest = remainder
		if len(rest) == 0 {
			break
		}
	}

	return lastCert
}

// verifyCertChain verifies that all root certificates match
func verifyCertChain(rootCerts []string) bool {
	if len(rootCerts) <= 1 {
		return true
	}

	first := rootCerts[0]
	for i := 1; i < len(rootCerts); i++ {
		if rootCerts[i] != "" && first != "" && rootCerts[i] != first {
			log.Printf("Warning: Certificate chain validation failed - root certificates don't match")
			return false
		}
	}

	return true
}
