package pckcertselect

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"
)

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

// extractTCBFromCert extracts TCB components from a PCK certificate
func extractTCBFromCert(cert *x509.Certificate) ([]byte, int, error) {
	// SGX PCK certificates have TCB in extensions
	// OID 1.2.840.113741.1.13.1 contains CPUSVN (16 bytes)
	// OID 1.2.840.113741.1.13.1.2 contains PCESVN (2 bytes)

	var cpusvn []byte
	var pcesvn int

	for _, ext := range cert.Extensions {
		// CPUSVN extension
		if ext.Id.String() == "1.2.840.113741.1.13.1.2" {
			// First 2 bytes after ASN.1 header are the extension data
			if len(ext.Value) >= 18 {
				// Skip ASN.1 SEQUENCE and OCTET STRING headers
				cpusvn = ext.Value[len(ext.Value)-16:]
			}
		}
		// PCESVN extension
		if ext.Id.String() == "1.2.840.113741.1.13.1.3" {
			if len(ext.Value) >= 4 {
				// Parse as integer (big endian)
				pcesvn = int(ext.Value[len(ext.Value)-2])<<8 | int(ext.Value[len(ext.Value)-1])
			}
		}
	}

	if cpusvn == nil {
		return nil, 0, fmt.Errorf("CPUSVN not found in certificate")
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
