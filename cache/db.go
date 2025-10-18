package cache

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/cockroachdb/pebble"
)

// DB wraps PebbleDB for caching SGX attestation collaterals
type DB struct {
	db *pebble.DB
}

// Open opens or creates a PebbleDB at the given path
func Open(path string) (*DB, error) {
	// Ensure directory exists
	if err := os.MkdirAll(path, 0755); err != nil {
		return nil, fmt.Errorf("failed to create db directory: %w", err)
	}

	db, err := pebble.Open(path, &pebble.Options{})
	if err != nil {
		return nil, fmt.Errorf("failed to open pebble db: %w", err)
	}

	return &DB{db: db}, nil
}

// Close closes the database
func (d *DB) Close() error {
	return d.db.Close()
}

// Key prefixes for different data types
const (
	prefixPlatform    = "platform:"
	prefixCert        = "cert:"
	prefixCertChain   = "certchain:"
	prefixTCB         = "tcb:"
	prefixIdentity    = "identity:"
	prefixCRL         = "crl:"
	prefixRootCRL     = "crl:root:"
	prefixCRLURI      = "crl:uri:"
	prefixPlatformTCB = "platform_tcb:"
	prefixRegistered  = "registered:"
)

// Platform operations

// GetPlatform retrieves platform information
func (d *DB) GetPlatform(qeID, pceID string) (*Platform, error) {
	key := fmt.Sprintf("%s%s:%s", prefixPlatform, qeID, pceID)
	value, closer, err := d.db.Get([]byte(key))
	if err != nil {
		if err == pebble.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	defer closer.Close()

	var platform Platform
	if err := json.Unmarshal(value, &platform); err != nil {
		return nil, err
	}
	return &platform, nil
}

// PutPlatform stores platform information
func (d *DB) PutPlatform(qeID, pceID string, platform *Platform) error {
	key := fmt.Sprintf("%s%s:%s", prefixPlatform, qeID, pceID)
	value, err := json.Marshal(platform)
	if err != nil {
		return err
	}
	return d.db.Set([]byte(key), value, pebble.Sync)
}

// Certificate operations

// GetCert retrieves a cached PCK certificate
func (d *DB) GetCert(qeID, pceID, tcbm string) ([]byte, error) {
	key := fmt.Sprintf("%s%s:%s:%s", prefixCert, qeID, pceID, tcbm)
	value, closer, err := d.db.Get([]byte(key))
	if err != nil {
		if err == pebble.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	defer closer.Close()

	result := make([]byte, len(value))
	copy(result, value)
	return result, nil
}

// PutCert stores a PCK certificate
func (d *DB) PutCert(qeID, pceID, tcbm string, cert []byte) error {
	key := fmt.Sprintf("%s%s:%s:%s", prefixCert, qeID, pceID, tcbm)
	return d.db.Set([]byte(key), cert, pebble.Sync)
}

// GetAllCerts retrieves all certificates for a platform
func (d *DB) GetAllCerts(qeID, pceID string) (map[string][]byte, error) {
	prefix := fmt.Sprintf("%s%s:%s:", prefixCert, qeID, pceID)
	iter, err := d.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte(prefix),
		UpperBound: []byte(prefix + "\xff"),
	})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	certs := make(map[string][]byte)
	for iter.First(); iter.Valid(); iter.Next() {
		key := string(iter.Key())
		tcbm := strings.TrimPrefix(key, prefix)

		value := make([]byte, len(iter.Value()))
		copy(value, iter.Value())
		certs[tcbm] = value
	}

	return certs, iter.Error()
}

// Certificate chain operations

// GetCertChain retrieves certificate chain for a CA
func (d *DB) GetCertChain(ca string) (*CertChain, error) {
	key := fmt.Sprintf("%s%s", prefixCertChain, ca)
	value, closer, err := d.db.Get([]byte(key))
	if err != nil {
		if err == pebble.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	defer closer.Close()

	var chain CertChain
	if err := json.Unmarshal(value, &chain); err != nil {
		return nil, err
	}
	return &chain, nil
}

// PutCertChain stores certificate chain for a CA
func (d *DB) PutCertChain(ca string, chain *CertChain) error {
	key := fmt.Sprintf("%s%s", prefixCertChain, ca)
	value, err := json.Marshal(chain)
	if err != nil {
		return err
	}
	return d.db.Set([]byte(key), value, pebble.Sync)
}

// TCB Info operations

// GetTCBInfo retrieves TCB information
func (d *DB) GetTCBInfo(prodType, fmspc, version, updateType string) ([]byte, error) {
	key := fmt.Sprintf("%s%s:%s:%s:%s", prefixTCB, prodType, fmspc, version, updateType)
	value, closer, err := d.db.Get([]byte(key))
	if err != nil {
		if err == pebble.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	defer closer.Close()

	result := make([]byte, len(value))
	copy(result, value)
	return result, nil
}

// PutTCBInfo stores TCB information
func (d *DB) PutTCBInfo(prodType, fmspc, version, updateType string, tcbInfo []byte) error {
	key := fmt.Sprintf("%s%s:%s:%s:%s", prefixTCB, prodType, fmspc, version, updateType)
	return d.db.Set([]byte(key), tcbInfo, pebble.Sync)
}

// GetAllFMSPCs returns all unique FMSPCs in the database
func (d *DB) GetAllFMSPCs() []string {
	iter, err := d.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte(prefixPlatform),
		UpperBound: []byte(prefixPlatform + "\xff"),
	})
	if err != nil {
		return nil
	}
	defer iter.Close()

	fmspcMap := make(map[string]bool)
	for iter.First(); iter.Valid(); iter.Next() {
		var platform Platform
		if err := json.Unmarshal(iter.Value(), &platform); err == nil && platform.FMSPC != "" {
			fmspcMap[platform.FMSPC] = true
		}
	}

	fmspcs := make([]string, 0, len(fmspcMap))
	for fmspc := range fmspcMap {
		fmspcs = append(fmspcs, fmspc)
	}
	return fmspcs
}

// Enclave Identity operations

// GetIdentity retrieves enclave identity
func (d *DB) GetIdentity(id, version, updateType string) ([]byte, error) {
	key := fmt.Sprintf("%s%s:%s:%s", prefixIdentity, id, version, updateType)
	value, closer, err := d.db.Get([]byte(key))
	if err != nil {
		if err == pebble.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	defer closer.Close()

	result := make([]byte, len(value))
	copy(result, value)
	return result, nil
}

// PutIdentity stores enclave identity
func (d *DB) PutIdentity(id, version, updateType string, identity []byte) error {
	key := fmt.Sprintf("%s%s:%s:%s", prefixIdentity, id, version, updateType)
	return d.db.Set([]byte(key), identity, pebble.Sync)
}

// CRL operations

// GetCRL retrieves a CRL for a CA
func (d *DB) GetCRL(ca string) ([]byte, error) {
	key := fmt.Sprintf("%s%s", prefixCRL, ca)
	value, closer, err := d.db.Get([]byte(key))
	if err != nil {
		if err == pebble.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	defer closer.Close()

	result := make([]byte, len(value))
	copy(result, value)
	return result, nil
}

// PutCRL stores a CRL for a CA
func (d *DB) PutCRL(ca string, crl []byte) error {
	key := fmt.Sprintf("%s%s", prefixCRL, ca)
	return d.db.Set([]byte(key), crl, pebble.Sync)
}

// GetRootCACRL retrieves root CA CRL
func (d *DB) GetRootCACRL(rootca string) ([]byte, error) {
	key := fmt.Sprintf("%s%s", prefixRootCRL, rootca)
	value, closer, err := d.db.Get([]byte(key))
	if err != nil {
		if err == pebble.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	defer closer.Close()

	result := make([]byte, len(value))
	copy(result, value)
	return result, nil
}

// PutRootCACRL stores root CA CRL
func (d *DB) PutRootCACRL(rootca string, crl []byte) error {
	key := fmt.Sprintf("%s%s", prefixRootCRL, rootca)
	return d.db.Set([]byte(key), crl, pebble.Sync)
}

// GetCRLByURI retrieves CRL by URI
func (d *DB) GetCRLByURI(uri string) ([]byte, error) {
	key := fmt.Sprintf("%s%s", prefixCRLURI, uri)
	value, closer, err := d.db.Get([]byte(key))
	if err != nil {
		if err == pebble.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	defer closer.Close()

	result := make([]byte, len(value))
	copy(result, value)
	return result, nil
}

// PutCRLByURI stores CRL by URI
func (d *DB) PutCRLByURI(uri string, crl []byte) error {
	key := fmt.Sprintf("%s%s", prefixCRLURI, uri)
	return d.db.Set([]byte(key), crl, pebble.Sync)
}

// Platform TCB operations

// GetPlatformTCB retrieves TCBm for a specific platform TCB level
func (d *DB) GetPlatformTCB(qeID, pceID, cpuSVN, pceSVN string) (string, error) {
	key := fmt.Sprintf("%s%s:%s:%s:%s", prefixPlatformTCB, qeID, pceID, cpuSVN, pceSVN)
	value, closer, err := d.db.Get([]byte(key))
	if err != nil {
		if err == pebble.ErrNotFound {
			return "", nil
		}
		return "", err
	}
	defer closer.Close()

	return string(value), nil
}

// PutPlatformTCB stores TCBm for a specific platform TCB level
func (d *DB) PutPlatformTCB(qeID, pceID, cpuSVN, pceSVN, tcbm string) error {
	key := fmt.Sprintf("%s%s:%s:%s:%s", prefixPlatformTCB, qeID, pceID, cpuSVN, pceSVN)
	return d.db.Set([]byte(key), []byte(tcbm), pebble.Sync)
}

// Registration queue operations (for OFFLINE mode)

// GetRegisteredPlatform retrieves a registered platform from queue
func (d *DB) GetRegisteredPlatform(qeID, pceID, cpuSVN, pceSVN string) (*RegisteredPlatform, error) {
	key := fmt.Sprintf("%s%s:%s:%s:%s", prefixRegistered, qeID, pceID, cpuSVN, pceSVN)
	value, closer, err := d.db.Get([]byte(key))
	if err != nil {
		if err == pebble.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	defer closer.Close()

	var regPlatform RegisteredPlatform
	if err := json.Unmarshal(value, &regPlatform); err != nil {
		return nil, err
	}
	return &regPlatform, nil
}

// PutRegisteredPlatform stores a registered platform in queue
func (d *DB) PutRegisteredPlatform(qeID, pceID, cpuSVN, pceSVN string, regPlatform *RegisteredPlatform) error {
	key := fmt.Sprintf("%s%s:%s:%s:%s", prefixRegistered, qeID, pceID, cpuSVN, pceSVN)
	value, err := json.Marshal(regPlatform)
	if err != nil {
		return err
	}
	return d.db.Set([]byte(key), value, pebble.Sync)
}

// DeleteRegisteredPlatform removes a registered platform from queue
func (d *DB) DeleteRegisteredPlatform(qeID, pceID, cpuSVN, pceSVN string) error {
	key := fmt.Sprintf("%s%s:%s:%s:%s", prefixRegistered, qeID, pceID, cpuSVN, pceSVN)
	return d.db.Delete([]byte(key), pebble.Sync)
}

// GetAllRegisteredPlatforms returns all registered platforms in queue
func (d *DB) GetAllRegisteredPlatforms() ([]*RegisteredPlatform, error) {
	iter, err := d.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte(prefixRegistered),
		UpperBound: []byte(prefixRegistered + "\xff"),
	})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var platforms []*RegisteredPlatform
	for iter.First(); iter.Valid(); iter.Next() {
		var regPlatform RegisteredPlatform
		if err := json.Unmarshal(iter.Value(), &regPlatform); err == nil {
			platforms = append(platforms, &regPlatform)
		}
	}

	return platforms, iter.Error()
}
