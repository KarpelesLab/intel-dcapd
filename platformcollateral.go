package main

import (
	"encoding/json"
)

// PlatformCollateral represents the bulk upload payload for OFFLINE mode
type PlatformCollateral struct {
	Platforms   []PlatformEntry `json:"platforms"`
	Collaterals Collaterals     `json:"collaterals"`
}

// PlatformEntry represents a platform in the bulk upload
type PlatformEntry struct {
	QEID             string `json:"qe_id"`
	PCEID            string `json:"pce_id"`
	CPUSVN           string `json:"cpu_svn,omitempty"`
	PCESVN           string `json:"pce_svn,omitempty"`
	EncPPID          string `json:"enc_ppid,omitempty"`
	PlatformManifest string `json:"platform_manifest,omitempty"`
}

// Collaterals contains all the collateral data
type Collaterals struct {
	Version      int                    `json:"version"`
	PCKCerts     []PCKCerts             `json:"pck_certs"`
	TCBInfos     []TCBInfoEntry         `json:"tcbinfos"`
	PCKCaCrl     *PCKCaCrl              `json:"pckcacrl,omitempty"`
	QEIdentity   json.RawMessage        `json:"qeidentity,omitempty"`
	QEIdentityEarly json.RawMessage     `json:"qeidentity_early,omitempty"`
	TDQEIdentity json.RawMessage        `json:"tdqeidentity,omitempty"`
	TDQEIdentityEarly json.RawMessage   `json:"tdqeidentity_early,omitempty"`
	QVEIdentity  json.RawMessage        `json:"qveidentity,omitempty"`
	QVEIdentityEarly json.RawMessage    `json:"qveidentity_early,omitempty"`
	Certificates CertificatesEntry      `json:"certificates"`
	RootCaCrl    string                 `json:"rootcacrl,omitempty"` // hex encoded
	RootCaCrlCdp string                 `json:"rootcacrl_cdp,omitempty"`
}

// PCKCerts represents PCK certificates for a platform
type PCKCerts struct {
	QEID             string        `json:"qe_id"`
	PCEID            string        `json:"pce_id"`
	EncPPID          string        `json:"enc_ppid,omitempty"`
	PlatformManifest string        `json:"platform_manifest,omitempty"`
	Certs            []PCKCertEntry `json:"certs"`
}

// PCKCertEntry represents a single PCK certificate
type PCKCertEntry struct {
	TCBM string `json:"tcbm"`
	Cert string `json:"cert"` // URL-encoded PEM
}

// TCBInfoEntry represents TCB information
type TCBInfoEntry struct {
	FMSPC           string          `json:"fmspc"`
	TCBInfo         json.RawMessage `json:"tcbinfo,omitempty"`          // v3 standard
	TCBInfoEarly    json.RawMessage `json:"tcbinfo_early,omitempty"`    // v3 early
	SGXTCBInfo      json.RawMessage `json:"sgx_tcbinfo,omitempty"`      // v4 sgx standard
	SGXTCBInfoEarly json.RawMessage `json:"sgx_tcbinfo_early,omitempty"` // v4 sgx early
	TDXTCBInfo      json.RawMessage `json:"tdx_tcbinfo,omitempty"`      // v4 tdx standard
	TDXTCBInfoEarly json.RawMessage `json:"tdx_tcbinfo_early,omitempty"` // v4 tdx early
}

// PCKCaCrl represents processor and platform CRLs
type PCKCaCrl struct {
	ProcessorCrl string `json:"processorCrl,omitempty"` // hex encoded
	PlatformCrl  string `json:"platformCrl,omitempty"`  // hex encoded
}

// CertificatesEntry represents certificate chains
type CertificatesEntry struct {
	PCKCertIssuerChain map[string]string `json:"SGX-PCK-Certificate-Issuer-Chain,omitempty"` // processor/platform -> chain
	TCBInfoIssuerChain string            `json:"SGX-TCB-Info-Issuer-Chain,omitempty"`       // v3
	TCBInfoIssuerChainV4 string          `json:"TCB-Info-Issuer-Chain,omitempty"`           // v4
	EnclaveIdentityIssuerChain string    `json:"SGX-Enclave-Identity-Issuer-Chain,omitempty"`
}
