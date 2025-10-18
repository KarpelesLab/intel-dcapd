package cache

// Platform represents a registered SGX platform
type Platform struct {
	QEID             string `json:"qe_id"`
	PCEID            string `json:"pce_id"`
	PlatformManifest string `json:"platform_manifest,omitempty"`
	EncPPID          string `json:"enc_ppid,omitempty"`
	FMSPC            string `json:"fmspc"`
	CA               string `json:"ca"` // "processor" or "platform"
}

// CertChain represents a certificate chain
type CertChain struct {
	CA        string `json:"ca"`
	RootCert  string `json:"root_cert"`
	IntmdCert string `json:"intmd_cert,omitempty"`
}

// RegisteredPlatform represents a platform in the registration queue (OFFLINE mode)
type RegisteredPlatform struct {
	QEID             string `json:"qe_id"`
	PCEID            string `json:"pce_id"`
	CPUSVN           string `json:"cpu_svn"`
	PCESVN           string `json:"pce_svn"`
	EncPPID          string `json:"enc_ppid,omitempty"`
	PlatformManifest string `json:"platform_manifest,omitempty"`
	State            int    `json:"state"` // 0 = new, 1 = not available, 9 = deleted
}

// Constants for product types
const (
	ProdTypeSGX = "sgx"
	ProdTypeTDX = "tdx"
)

// Constants for update types
const (
	UpdateTypeStandard = "standard"
	UpdateTypeEarly    = "early"
)

// Constants for enclave identity IDs
const (
	IdentityQE   = "1" // QE (Quoting Enclave)
	IdentityQVE  = "2" // QVE (Quote Verification Enclave)
	IdentityTDQE = "3" // TDQE (TD Quoting Enclave)
)

// Constants for CA types
const (
	CAProcessor = "processor"
	CAPlatform  = "platform"
)

// Constants for registration states
const (
	PlatformRegNew          = 0
	PlatformRegNotAvailable = 1
	PlatformRegDeleted      = 9
)
