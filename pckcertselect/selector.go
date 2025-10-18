package pckcertselect

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"strconv"
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

// comparisonResult represents the result of comparing two TCB values
type comparisonResult int

const (
	compError          comparisonResult = iota // Error in comparison
	compLower                                   // Left < Right
	compEqualOrGreater                          // Left >= Right (all components)
	compUndefined                               // Incomparable (some higher, some lower)
)

// certWithTCB holds a certificate index and its extracted TCB
type certWithTCB struct {
	index   int
	cpusvn  []byte
	pcesvn  int
	certPEM string
}

// SelectCertificate selects the best matching PCK certificate based on TCB levels
// Returns the index of the selected certificate, or -1 if no match found
// Algorithm matches Intel's PCKCertSelection library
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

	// Extract TCB from all certificates
	var certsWithTCB []certWithTCB
	for i, certPEM := range certs {
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			logVerbose("Certificate %d: failed to decode PEM", i)
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			logVerbose("Certificate %d: failed to parse x509: %v", i, err)
			continue
		}

		certCPUSVN, certPCESVN, err := extractTCBFromCert(cert)
		if err != nil {
			logVerbose("Certificate %d: failed to extract TCB: %v", i, err)
			continue
		}

		certsWithTCB = append(certsWithTCB, certWithTCB{
			index:   i,
			cpusvn:  certCPUSVN,
			pcesvn:  certPCESVN,
			certPEM: certPEM,
		})
		logVerbose("Certificate %d: CPUSVN=%x PCESVN=%d", i, certCPUSVN, certPCESVN)
	}

	if len(certsWithTCB) == 0 {
		return -1, fmt.Errorf("no valid certificates with TCB extensions")
	}

	// Sort certificates by TCB (highest first)
	// This matches Intel's bucketing approach
	sortCertsByTCB(certsWithTCB)

	// Find first certificate where platform_tcb >= cert_tcb
	// This gives us the highest valid certificate
	logVerbose("Platform TCB: CPUSVN=%x PCESVN=%d", targetCPUSVN, targetPCESVN)
	for i, certTCB := range certsWithTCB {
		result := compareTCBComponents(targetCPUSVN, int(targetPCESVN), certTCB.cpusvn, certTCB.pcesvn)
		logVerbose("Comparing platform to cert %d (orig index %d): %s", i, certTCB.index, compResultString(result))

		if result == compEqualOrGreater {
			logVerbose("Selected certificate at original index %d", certTCB.index)
			return certTCB.index, nil
		}
	}

	return -1, fmt.Errorf("platform TCB is lower than all available certificates")
}

// compResultString returns a string representation of comparison result
func compResultString(r comparisonResult) string {
	switch r {
	case compError:
		return "ERROR"
	case compLower:
		return "LOWER"
	case compEqualOrGreater:
		return "EQUAL_OR_GREATER"
	case compUndefined:
		return "UNDEFINED"
	default:
		return "UNKNOWN"
	}
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
	// Find the base SGX extensions OID
	var sgxExtValue []byte
	for _, ext := range cert.Extensions {
		if ext.Id.String() == SGXExtensionsOID {
			sgxExtValue = ext.Value
			logVerbose("Found base SGX extension: OID=%s len=%d", SGXExtensionsOID, len(ext.Value))
			break
		}
	}

	if sgxExtValue == nil {
		return nil, 0, fmt.Errorf("SGX extensions not found (looked for OID %s)", SGXExtensionsOID)
	}

	// Parse the nested ASN.1 structure
	// The extension value contains a SEQUENCE of nested OID/value pairs
	cpusvn, pcesvn, err := parseSGXExtensions(sgxExtValue)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse SGX extensions: %w", err)
	}

	logVerbose("  Extracted CPUSVN: %x", cpusvn)
	logVerbose("  Extracted PCESVN: %d (0x%04x)", pcesvn, pcesvn)

	return cpusvn, pcesvn, nil
}

// parseSGXExtensions parses the nested ASN.1 structure inside the base SGX extension
func parseSGXExtensions(extValue []byte) ([]byte, int, error) {
	// The structure is a SEQUENCE containing nested elements
	// Each element is a SEQUENCE of [OID, value]

	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(extValue, &seq)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to unmarshal base sequence: %w", err)
	}
	if len(rest) > 0 {
		logVerbose("Warning: %d bytes remaining after base sequence", len(rest))
	}

	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence {
		return nil, 0, fmt.Errorf("expected SEQUENCE, got class=%d tag=%d", seq.Class, seq.Tag)
	}

	// Parse the sequence contents
	var cpusvn []byte
	var pcesvn int
	var foundCPUSVN, foundPCESVN bool

	data := seq.Bytes
	for len(data) > 0 {
		var item asn1.RawValue
		var err error
		data, err = asn1.Unmarshal(data, &item)
		if err != nil {
			logVerbose("Warning: failed to unmarshal item: %v", err)
			break
		}

		if item.Class != asn1.ClassUniversal || item.Tag != asn1.TagSequence {
			continue
		}

		// Parse [OID, value] pair
		var oid asn1.ObjectIdentifier
		var value asn1.RawValue
		itemData := item.Bytes

		itemData, err = asn1.Unmarshal(itemData, &oid)
		if err != nil {
			continue
		}

		_, err = asn1.Unmarshal(itemData, &value)
		if err != nil {
			continue
		}

		oidStr := oid.String()
		logVerbose("  Found nested OID: %s (tag=%d, len=%d)", oidStr, value.Tag, len(value.Bytes))

		// Check for TCB extension - exact OID match only
		if oidStr == SGXExtensionsTCB && value.Tag == asn1.TagSequence {
			logVerbose("  -> Found TCB sequence, parsing nested contents...")
			cpusvnFound, pcesvnFound, err := parseTCBSequence(value.Bytes)
			if err == nil {
				cpusvn = cpusvnFound
				pcesvn = pcesvnFound
				foundCPUSVN = true
				foundPCESVN = true
				logVerbose("  -> Successfully extracted TCB values from nested sequence")
			} else {
				logVerbose("  -> Failed to parse TCB sequence: %v", err)
			}
		}
	}

	if !foundCPUSVN {
		return nil, 0, fmt.Errorf("CPUSVN not found in SGX extensions")
	}
	if !foundPCESVN {
		return nil, 0, fmt.Errorf("PCESVN not found in SGX extensions")
	}

	return cpusvn, pcesvn, nil
}

// parseTCBSequence parses the TCB sequence to extract CPUSVN and PCESVN
func parseTCBSequence(tcbBytes []byte) ([]byte, int, error) {
	var cpusvn []byte
	var pcesvn int
	var foundCPUSVN, foundPCESVN bool

	data := tcbBytes
	for len(data) > 0 {
		var item asn1.RawValue
		var err error
		data, err = asn1.Unmarshal(data, &item)
		if err != nil {
			logVerbose("    Warning: failed to unmarshal TCB item: %v", err)
			break
		}

		if item.Class != asn1.ClassUniversal || item.Tag != asn1.TagSequence {
			continue
		}

		// Parse [OID, value] pair
		var oid asn1.ObjectIdentifier
		var value asn1.RawValue
		itemData := item.Bytes

		itemData, err = asn1.Unmarshal(itemData, &oid)
		if err != nil {
			continue
		}

		_, err = asn1.Unmarshal(itemData, &value)
		if err != nil {
			continue
		}

		oidStr := oid.String()
		logVerbose("    Found TCB component OID: %s (tag=%d, len=%d)", oidStr, value.Tag, len(value.Bytes))

		// Check for CPUSVN - exact OID match only
		if oidStr == SGXExtensionsCPUSVN {
			if value.Tag == asn1.TagOctetString && len(value.Bytes) >= 16 {
				cpusvn = make([]byte, 16)
				copy(cpusvn, value.Bytes[:16])
				foundCPUSVN = true
				logVerbose("    -> CPUSVN found: %x", cpusvn)
			} else {
				logVerbose("    -> CPUSVN OID matched but wrong tag/length: tag=%d len=%d", value.Tag, len(value.Bytes))
			}
		}

		// Check for PCESVN - exact OID match only
		if oidStr == SGXExtensionsPCESVN {
			if value.Tag == asn1.TagInteger && len(value.Bytes) >= 1 {
				// Parse integer (big-endian)
				pcesvn = 0
				for _, b := range value.Bytes {
					pcesvn = (pcesvn << 8) | int(b)
				}
				foundPCESVN = true
				logVerbose("    -> PCESVN found: %d (0x%04x)", pcesvn, pcesvn)
			} else {
				logVerbose("    -> PCESVN OID matched but wrong tag/length: tag=%d len=%d", value.Tag, len(value.Bytes))
			}
		}
	}

	if !foundCPUSVN {
		return nil, 0, fmt.Errorf("CPUSVN not found in TCB sequence")
	}
	if !foundPCESVN {
		return nil, 0, fmt.Errorf("PCESVN not found in TCB sequence")
	}

	return cpusvn, pcesvn, nil
}

// compareTCBComponents compares two TCB values using Intel's algorithm
// Matches the logic from PCKCertSelection library's compare_tcb_components
func compareTCBComponents(leftCPUSVN []byte, leftPCESVN int, rightCPUSVN []byte, rightPCESVN int) comparisonResult {
	if len(leftCPUSVN) != 16 || len(rightCPUSVN) != 16 {
		return compError
	}

	leftLower := false
	rightLower := false

	// Compare PCESVNs
	if leftPCESVN < rightPCESVN {
		leftLower = true
	}
	if leftPCESVN > rightPCESVN {
		rightLower = true
	}

	// Compare components byte by byte
	for i := 0; i < 16; i++ {
		if leftCPUSVN[i] < rightCPUSVN[i] {
			leftLower = true
		}
		if leftCPUSVN[i] > rightCPUSVN[i] {
			rightLower = true
		}
	}

	// Determine result based on flags
	if leftLower && rightLower {
		return compUndefined // Some components higher, some lower
	}
	if leftLower {
		return compLower // Left is strictly lower
	}
	return compEqualOrGreater // Left >= Right in all components
}

// sortCertsByTCB sorts certificates by TCB in descending order (highest first)
// This matches Intel's bucketing approach
func sortCertsByTCB(certs []certWithTCB) {
	// Simple bubble sort since certificate count is typically small (< 20)
	// Could use sort.Slice but this is clearer and matches Intel's approach
	for i := 0; i < len(certs); i++ {
		for j := i + 1; j < len(certs); j++ {
			// Compare certs[i] with certs[j]
			result := compareTCBComponents(certs[i].cpusvn, certs[i].pcesvn, certs[j].cpusvn, certs[j].pcesvn)
			// If certs[i] is lower than certs[j], swap them (we want highest first)
			if result == compLower {
				certs[i], certs[j] = certs[j], certs[i]
			}
		}
	}
}
