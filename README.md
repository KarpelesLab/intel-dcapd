# Intel DCAP Provisioning Certificate Caching Service (Go)

> **IMPORTANT NOTICE**
> This is **NOT** official Intel software. This is an independent, community-developed implementation of a caching proxy for Intel's SGX Provisioning Certificate Service. It is not affiliated with, endorsed by, or supported by Intel Corporation.
>
> Use at your own risk. For official Intel software, please visit the [Intel SGX DCAP repository](https://github.com/intel/SGXDataCenterAttestationPrimitives).

A lightweight, self-contained replacement for Intel's SGX DCAP PCCS (Provisioning Certificate Caching Service), written in Go.

This service acts as a caching proxy between SGX-enabled platforms and Intel's Provisioning Certificate Service, reducing network latency and dependency on external services during SGX quote generation and verification.

## Why This Replacement?

The original Node.js-based PCCS (`sgx-dcap-pccs`) has become difficult to install due to:
- Deprecated npm packages that can no longer be installed
- Complex dependency chains
- Heavy runtime requirements (Node.js, native modules, etc.)
- apt install requires interactions

This Go implementation:
- **Single binary** - no dependencies, just run it
- **In-memory TLS certificates** - auto-generates self-signed certs if needed
- **Minimal configuration** - only requires an API key
- **Lightweight** - uses PebbleDB for caching instead of SQL
- **Drop-in compatible** - implements the same API as the original PCCS

## Installation

### Pre-built Binaries (Recommended)

Download the latest release from [GitHub Releases](https://github.com/KarpelesLab/intel-dcapd/releases):

**Linux (x86_64):**
```bash
wget https://github.com/KarpelesLab/intel-dcapd/releases/latest/download/intel-dcapd-linux-amd64.tar.gz
tar -xzf intel-dcapd-linux-amd64.tar.gz
cd intel-dcapd-linux-amd64-*/
sudo cp intel-dcapd /usr/local/bin/
sudo cp pccsadmin /usr/local/bin/
```

**Linux (i386):**
```bash
wget https://github.com/KarpelesLab/intel-dcapd/releases/latest/download/intel-dcapd-linux-i386.tar.gz
tar -xzf intel-dcapd-linux-i386.tar.gz
cd intel-dcapd-linux-i386-*/
sudo cp intel-dcapd /usr/local/bin/
sudo cp pccsadmin /usr/local/bin/
```

**Windows (x86_64):**
```powershell
# Download: https://github.com/KarpelesLab/intel-dcapd/releases/latest/download/intel-dcapd-windows-amd64.zip
# Extract the zip file
# Run intel-dcapd.exe and pccsadmin.exe from the extracted folder
```

Each release includes:
- `intel-dcapd` - Main PCCS service binary
- `pccsadmin` - Administration CLI tool for managing PCCS
- `README.md` - Main documentation
- `README.pccsadmin.md` - Administration tool documentation
- `LICENSE` - License information

### Build from Source

```bash
git clone https://github.com/KarpelesLab/intel-dcapd.git
cd intel-dcapd
go build -o intel-dcapd
```

Requirements: Go 1.23 or later

## Quick Start

### 1. Get an Intel API Key

Subscribe to Intel's Provisioning Certificate Service:
https://api.portal.trustedservices.intel.com/provisioning-certification

### 2. Run the Service

```bash
export INTEL_API_KEY=your-api-key-here
./intel-dcapd
```

That's it! The service will:
- Listen on `https://localhost:8081`
- Auto-generate a self-signed TLS certificate (in-memory)
- Store cache in `~/.cache/intel-dcapd/cachedb`
- Start serving requests

### 3. Configure Your SGX Client

Edit `/etc/sgx_default_qcnl.conf`:

```json
{
  "pccs_url": "https://localhost:8081/sgx/certification/v4/",
  "use_secure_cert": false
}
```

## Configuration

All configuration is via environment variables:

### Required

- **`INTEL_API_KEY`** - Your Intel PCS API subscription key (required)

### Optional

- **`DCAPD_LISTEN`** - Listen address (default: `localhost:8081`)
- **`DCAPD_DB_PATH`** - Database path (default: `~/.cache/intel-dcapd/cachedb`)
- **`DCAPD_CACHE_MODE`** - Caching mode: `LAZY`, `REQ`, or `OFFLINE` (default: `LAZY`)
- **`DCAPD_PCS_URL`** - Intel PCS URL (default: `https://api.trustedservices.intel.com/sgx/certification/v4/`)
- **`DCAPD_VERBOSE`** - Enable verbose logging: `1` or `true` (default: disabled)

### TLS Certificate (Optional)

- **`DCAPD_CERT_FILE`** - Path to TLS certificate (if not set, auto-generates in-memory)
- **`DCAPD_KEY_FILE`** - Path to TLS private key (if not set, auto-generates in-memory)

### Authentication (Optional)

- **`DCAPD_USER_TOKEN_SHA512`** - SHA-512 hash of user token for platform registration
- **`DCAPD_ADMIN_TOKEN_SHA512`** - SHA-512 hash of admin token for admin endpoints

## Caching Modes

### LAZY Mode (Default)

Cache-on-demand: fetches from Intel PCS when data is not in cache.

- Requires internet access at runtime
- Best for development and testing
- Automatic cache population
- **Fully supported**

### REQ Mode

Pre-caches platform data during registration.

- Fetches all collaterals when platform is registered via POST /platforms
- Runtime uses cache only (no Intel PCS access needed)
- Good for production with initial internet access
- **Fully supported**

### OFFLINE Mode

No internet access required at runtime.

- **Fully supported**
- Platform registration via POST /platforms works (fetches and caches if internet available)
- Manual collateral upload via PUT /platformcollateral is **FULLY IMPLEMENTED**
- Supports bulk upload of platforms, certificates, TCB info, CRLs, and identities
- True air-gapped deployment ready

## Feature Status

| Feature | Status | Notes |
|---------|--------|-------|
| PCK Certificate caching | Fully supported | GET /pckcert |
| TCB Info (SGX & TDX) | Fully supported | Both v3 and v4 APIs |
| Enclave identities | Fully supported | QE, QVE, TDQE |
| CRL caching | Fully supported | PCK, Root CA, generic |
| Platform registration | Fully supported | POST /platforms |
| Platform listing | Fully supported | GET /platforms |
| Manual cache refresh | Fully supported | GET/POST /refresh |
| Appraisal policies | Fully supported | PUT/GET /appraisalpolicy |
| Platform collateral upload | Fully supported | PUT /platformcollateral (OFFLINE mode) |
| Background cache refresh | Fully supported | Automatic daily refresh |
| v3 API compatibility | Fully supported | All endpoints support v3 |
| v4 API | Fully supported | Primary API version |

## API Endpoints

The service implements the Intel PCCS API with full v3 and v4 support:

### Certificate Endpoints (Public)

```
GET  /sgx/certification/v4/pckcert              # Get PCK certificate
GET  /sgx/certification/v4/tcb                  # Get SGX TCB info
GET  /sgx/certification/v4/qe/identity          # Get QE identity
GET  /sgx/certification/v4/qve/identity         # Get QVE identity
GET  /sgx/certification/v4/pckcrl               # Get PCK CRL
GET  /sgx/certification/v4/rootcacrl            # Get root CA CRL
GET  /sgx/certification/v4/crl                  # Get CRL from URL
GET  /sgx/certification/v4/appraisalpolicy      # Get appraisal policy
```

### Platform Management (Authenticated)

```
POST /sgx/certification/v4/platforms            # Register platforms (user auth)
GET  /sgx/certification/v4/platforms            # List platforms (admin auth)
```

### Admin Endpoints (Authenticated)

```
GET  /sgx/certification/v4/refresh              # Trigger cache refresh
POST /sgx/certification/v4/refresh              # Trigger cache refresh
PUT  /sgx/certification/v4/appraisalpolicy      # Upload appraisal policy
PUT  /sgx/certification/v4/platformcollateral   # Bulk upload collateral (OFFLINE mode)
```

### TDX Endpoints (Public)

```
GET  /tdx/certification/v4/tcb                  # Get TDX TCB info
GET  /tdx/certification/v4/qe/identity          # Get TD QE identity
```

**Note:** All endpoints above are also available with `/v3/` for backward compatibility.

## Differences from Intel's Node.js PCCS

This Go implementation achieves API compatibility with Intel's reference PCCS but differs in some areas:

### Implementation Differences
- **Database:** Uses PebbleDB (embedded key-value store) instead of SQLite/MySQL
  - No schema migrations needed
  - Simpler deployment
  - Cannot migrate existing PCCS database (cache repopulates automatically)

- **Platform Registration:** POST /platforms in LAZY/REQ modes fetches certificates immediately
  - Simpler than Intel's queuing mechanism
  - No separate platform registration states ("NEW", "NOT_AVAILABLE")
  - Platforms are either cached or not cached

- **Certificate Selection:** Pure Go implementation of PCK certificate selection algorithm
  - Based on Intel's reference but independently implemented
  - Matches PCK cert to platform TCB level

### Fully Compatible
- All certificate retrieval endpoints (GET /pckcert, /tcb, /qe/identity, etc.)
- Platform collateral bulk upload (PUT /platformcollateral)
- Both v3 and v4 API versions
- Authentication model (user/admin tokens)
- Cache refresh mechanism
- Appraisal policy storage and retrieval
- OFFLINE mode for air-gapped deployments

## Deployment

### Systemd Service

Create `/etc/systemd/system/intel-dcapd.service`:

```ini
[Unit]
Description=Intel DCAP Provisioning Certificate Caching Service
After=network.target

[Service]
Type=simple
User=dcapd
Environment="INTEL_API_KEY=your-key-here"
ExecStart=/usr/local/bin/intel-dcapd
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable intel-dcapd
sudo systemctl start intel-dcapd
```

### Docker

```dockerfile
FROM golang:1.23-alpine AS builder
WORKDIR /build
COPY . .
RUN go build -o intel-dcapd

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /build/intel-dcapd /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/intel-dcapd"]
```

Run:

```bash
docker build -t intel-dcapd .
docker run -d -p 8081:8081 -e INTEL_API_KEY=your-key intel-dcapd
```

## Production Use

For production deployments:

1. **Use proper TLS certificates**:
   ```bash
   export DCAPD_CERT_FILE=/path/to/cert.pem
   export DCAPD_KEY_FILE=/path/to/key.pem
   ```

2. **Enable authentication**:
   ```bash
   # Generate token hash (example with openssl)
   echo -n "my-secret-token" | openssl dgst -sha512 | awk '{print $2}'

   export DCAPD_USER_TOKEN_SHA512=<hash>
   export DCAPD_ADMIN_TOKEN_SHA512=<hash>
   ```

3. **Listen on all interfaces** (if needed):
   ```bash
   export DCAPD_LISTEN=0.0.0.0:8081
   ```

## Migrating from Node.js PCCS

The Go implementation uses PebbleDB instead of SQLite/MySQL, so you cannot directly migrate the database. However, the cache will be automatically repopulated on-demand as platforms request certificates.

Steps:
1. Stop the old PCCS service
2. Start the Go version with the same API key
3. Test with a few platforms
4. Monitor logs for any issues

## Logging

Logs go to standard output. Key events logged:
- Server startup and configuration
- TLS certificate generation
- Cache hits/misses
- Intel PCS requests (with Request-ID for debugging)
- Errors and warnings

## Troubleshooting

### Enable Verbose Logging

For detailed debugging information:

```bash
export DCAPD_VERBOSE=1
./intel-dcapd
```

Verbose mode logs:
- All request parameters
- Cache hits and misses
- Certificate selection process
- Intel PCS request/response details
- Certificate and issuer chain lengths
- Response headers being sent

### "INTEL_API_KEY environment variable is required"

You need to set the API key. Get one from: https://api.portal.trustedservices.intel.com/

### Certificate errors from SGX clients

Set `"use_secure_cert": false` in `/etc/sgx_default_qcnl.conf` if using auto-generated certificates.

### Platform not found

- Check that the API key is valid
- Verify internet connectivity to Intel PCS
- Check logs for Intel PCS errors
- Ensure the platform has been properly registered
- **Enable verbose logging** to see detailed request flow

### "No certificate data for this platform"

This can indicate certificate encoding issues:

1. Enable verbose logging: `export DCAPD_VERBOSE=1`
2. Clear the cache: `rm -rf ~/.cache/intel-dcapd/cachedb`
3. Restart the service
4. Check verbose logs for certificate lengths and encoding
5. Verify AESM is using the correct PCCS URL in `/etc/sgx_default_qcnl.conf`

## License and Disclaimer

This is an independent, community-developed implementation and is **NOT** official Intel software.

**Disclaimer:** This software is provided "as-is" without warranty of any kind. Intel Corporation does not endorse, support, or maintain this implementation. The authors and contributors are not responsible for any issues arising from the use of this software.

For official Intel software and licensing information regarding Intel SGX technologies, please refer to:
- [Intel SGX DCAP Official Repository](https://github.com/intel/SGXDataCenterAttestationPrimitives)
- [Intel SGX Developer Resources](https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/overview.html)

This implementation is intended to interface with Intel's Provisioning Certificate Service API, which requires a valid API key from Intel. Users must comply with Intel's terms of service when using their PCS API.

## Contributing

This is a pragmatic, minimal implementation. Contributions should focus on:
- Bug fixes
- Security improvements
- Performance optimizations
- Better error handling

Keep it simple!

