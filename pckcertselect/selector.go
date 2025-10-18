package pckcertselect

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"strconv"
	"strings"
)

// Global verbose flag for this package
var verbose bool

// SetVerbose enables or disables verbose logging
func SetVerbose(v bool) {
	verbose = v
}

// logVerbose logs a message only if verbose mode is enabled
func logVerbose(format string, v ...interface{}) {
	if verbose {
		log.Printf("[VERBOSE] "+format, v...)
	}
}

// TCBInfo represents the TCB information from Intel PCS
type TCBInfo struct {
	TCBInfo struct {
		Version    int `json:"version"`
		IssueDate  string `json:"issueDate"`
		NextUpdate string `json:"nextUpdate"`
		FMSPC      string `json:"fmspc"`
		PCEId      string `json:"pceId"`
		TCBType    int    `json:"tcbType"`
		TCBLevels  []struct {
			TCB struct {
				SGXTCBComp01SVN int `json:"sgxtcbcomp01svn"`
				SGXTCBComp02SVN int `json:"sgxtcbcomp02svn"`
				SGXTCBComp03SVN int `json:"sgxtcbcomp03svn"`
				SGXTCBComp04SVN int `json:"sgxtcbcomp04svn"`
				SGXTCBComp05SVN int `json:"sgxtcbcomp05svn"`
				SGXTCBComp06SVN int `json:"sgxtcbcomp06svn"`
				SGXTCBComp07SVN int `json:"sgxtcbcomp07svn"`
				SGXTCBComp08SVN int `json:"sgxtcbcomp08svn"`
				SGXTCBComp09SVN int `json:"sgxtcbcomp09svn"`
				SGXTCBComp10SVN int `json:"sgxtcbcomp10svn"`
				SGXTCBComp11SVN int `json:"sgxtcbcomp11svn"`
				SGXTCBComp12SVN int `json:"sgxtcbcomp12svn"`
				SGXTCBComp13SVN int `json:"sgxtcbcomp13svn"`
				SGXTCBComp14SVN int `json:"sgxtcbcomp14svn"`
				SGXTCBComp15SVN int `json:"sgxtcbcomp15svn"`
				SGXTCBComp16SVN int `json:"sgxtcbcomp16svn"`
				PCESVN          int `json:"pcesvn"`
			} `json:"tcb"`
			TCBDate   string `json:"tcbDate"`
			TCBStatus string `json:"tcbStatus"`
		} `json:"tcbLevels"`
	} `json:"tcbInfo"`
}

// SelectCertificate selects the best matching PCK certificate based on TCB levels
// Returns the index of the selected certificate, or -1 if no match found
func SelectCertificate(certs []string, cpuSVN, pceSVN, pceID string, tcbInfoJSON []byte) (int, error) {
	if len(certs) == 0 {
		return -1, fmt.Errorf("no certificates provided")
	}

	// Parse TCB info
	var tcbInfo TCBInfo
	if err := json.Unmarshal(tcbInfoJSON, &tcbInfo); err != nil {
		return -1, fmt.Errorf("failed to parse TCB info: %w", err)
	}

	// Parse target CPUSVN (32 hex chars = 16 bytes)
	if len(cpuSVN) != 32 {
		return -1, fmt.Errorf("invalid CPUSVN length: %d", len(cpuSVN))
	}

	targetCPUSVN, err := hex.DecodeString(cpuSVN)
	if err != nil {
		return -1, fmt.Errorf("invalid CPUSVN hex: %w", err)
	}

	// Parse target PCESVN
	targetPCESVN, err := strconv.ParseInt(pceSVN, 16, 32)
	if err != nil {
		return -1, fmt.Errorf("invalid PCESVN: %w", err)
	}

	// Extract TCB components from each certificate and find best match
	bestIdx := -1
	bestScore := -1

	for i, certPEM := range certs {
		// Parse certificate
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		// Extract TCB from certificate extensions
		// SGX PCK certificates have TCB info in extensions
		certCPUSVN, certPCESVN, err := extractTCBFromCert(cert)
		if err != nil {
			continue
		}

		// Check if this cert's TCB matches or is greater than target
		score := compareTCB(targetCPUSVN, int(targetPCESVN), certCPUSVN, certPCESVN, &tcbInfo)
		if score > bestScore {
			bestScore = score
			bestIdx = i
		}
	}

	if bestIdx == -1 {
		return -1, fmt.Errorf("no matching certificate found")
	}

	return bestIdx, nil
}

// SGX extension OID constants
const (
	// Base SGX extensions OID
	SGXExtensionsOID = "1.2.840.113741.1.13.1"

	// TCB extensions (nested under base)
	SGXExtensionsPPID      = "1.2.840.113741.1.13.1.1"
	SGXExtensionsTCB       = "1.2.840.113741.1.13.1.2"
	SGXExtensionsPCEID     = "1.2.840.113741.1.13.1.3"
	SGXExtensionsFMSPC     = "1.2.840.113741.1.13.1.4"
	SGXExtensionsSGXType   = "1.2.840.113741.1.13.1.5"

	// Individual TCB components (nested under .2)
	SGXExtensionsTCBComp01SVN = "1.2.840.113741.1.13.1.2.1"
	SGXExtensionsTCBComp02SVN = "1.2.840.113741.1.13.1.2.2"
	SGXExtensionsTCBComp03SVN = "1.2.840.113741.1.13.1.2.3"
	SGXExtensionsTCBComp04SVN = "1.2.840.113741.1.13.1.2.4"
	SGXExtensionsTCBComp05SVN = "1.2.840.113741.1.13.1.2.5"
	SGXExtensionsTCBComp06SVN = "1.2.840.113741.1.13.1.2.6"
	SGXExtensionsTCBComp07SVN = "1.2.840.113741.1.13.1.2.7"
	SGXExtensionsTCBComp08SVN = "1.2.840.113741.1.13.1.2.8"
	SGXExtensionsTCBComp09SVN = "1.2.840.113741.1.13.1.2.9"
	SGXExtensionsTCBComp10SVN = "1.2.840.113741.1.13.1.2.10"
	SGXExtensionsTCBComp11SVN = "1.2.840.113741.1.13.1.2.11"
	SGXExtensionsTCBComp12SVN = "1.2.840.113741.1.13.1.2.12"
	SGXExtensionsTCBComp13SVN = "1.2.840.113741.1.13.1.2.13"
	SGXExtensionsTCBComp14SVN = "1.2.840.113741.1.13.1.2.14"
	SGXExtensionsTCBComp15SVN = "1.2.840.113741.1.13.1.2.15"
	SGXExtensionsTCBComp16SVN = "1.2.840.113741.1.13.1.2.16"
	SGXExtensionsPCESVN       = "1.2.840.113741.1.13.1.2.17"
	SGXExtensionsCPUSVN       = "1.2.840.113741.1.13.1.2.18"
)

// extractTCBFromCert extracts TCB components from a PCK certificate
func extractTCBFromCert(cert *x509.Certificate) ([]byte, int, error) {
	var cpusvn []byte
	var pcesvn int
	var foundCPUSVN, foundPCESVN bool

	// Debug: log all SGX extension OIDs present
	logVerbose("Certificate has %d extensions total", len(cert.Extensions))
	for _, ext := range cert.Extensions {
		oidStr := ext.Id.String()
		if strings.HasPrefix(oidStr, SGXExtensionsOID) {
			logVerbose("  Found SGX extension: OID=%s len=%d", oidStr, len(ext.Value))
		}

		// CPUSVN extension
		if oidStr == SGXExtensionsCPUSVN {
			if len(ext.Value) >= 16 {
				cpusvn = ext.Value[len(ext.Value)-16:]
				foundCPUSVN = true
				logVerbose("  Extracted CPUSVN: %x", cpusvn)
			}
		}
		// PCESVN extension
		if oidStr == SGXExtensionsPCESVN {
			if len(ext.Value) >= 2 {
				// Parse as 2-byte integer (little endian)
				pcesvn = int(ext.Value[len(ext.Value)-1])<<8 | int(ext.Value[len(ext.Value)-2])
				foundPCESVN = true
				logVerbose("  Extracted PCESVN: %d (0x%04x)", pcesvn, pcesvn)
			}
		}
	}

	if !foundCPUSVN {
		return nil, 0, fmt.Errorf("CPUSVN not found in certificate (looked for OID %s)", SGXExtensionsCPUSVN)
	}
	if !foundPCESVN {
		return nil, 0, fmt.Errorf("PCESVN not found in certificate (looked for OID %s)", SGXExtensionsPCESVN)
	}

	return cpusvn, pcesvn, nil
}

// compareTCB compares target TCB with certificate TCB and returns a match score
// Higher score = better match
// Returns -1 if cert TCB is lower than target (not acceptable)
func compareTCB(targetCPUSVN []byte, targetPCESVN int, certCPUSVN []byte, certPCESVN int, tcbInfo *TCBInfo) int {
	// Check PCESVN first
	if certPCESVN < targetPCESVN {
		return -1 // Certificate PCESVN is too low
	}

	// Check each CPUSVN component
	for i := 0; i < 16 && i < len(targetCPUSVN) && i < len(certCPUSVN); i++ {
		if certCPUSVN[i] < targetCPUSVN[i] {
			return -1 // Certificate CPUSVN component is too low
		}
	}

	// Calculate match score (prefer exact matches)
	score := 0

	// Exact PCESVN match is better
	if certPCESVN == targetPCESVN {
		score += 100
	}

	// Count exact CPUSVN component matches
	for i := 0; i < 16 && i < len(targetCPUSVN) && i < len(certCPUSVN); i++ {
		if certCPUSVN[i] == targetCPUSVN[i] {
			score += 10
		}
	}

	return score
}
