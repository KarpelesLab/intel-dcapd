# PCCS Administrator Tool

A command-line tool for managing Intel SGX DCAP PCCS (Provisioning Certificate Caching Service).

This is a Go reimplementation of Intel's Python-based PccsAdminTool, designed to be more lightweight and easier to use.

## Installation

### Using go install

```bash
go install github.com/KarpelesLab/intel-dcapd/tools/pccsadmin@latest
```

### Build from source

```bash
cd tools/pccsadmin
go build -o pccsadmin
```

### Run without installation

```bash
go run github.com/KarpelesLab/intel-dcapd/tools/pccsadmin@latest <command> [options]
```

## Usage

```
pccsadmin <command> [options]
```

### Available Commands

- `get` - Get platform registration data from PCCS
- `put` - Upload platform collateral or appraisal policy to PCCS
- `fetch` - Fetch platform collateral from Intel PCS
- `collect` - Collect platform data from CSV files
- `refresh` - Request PCCS to refresh cached data

## Commands

### get - Get Platform Data from PCCS

Get registered platform data from PCCS service.

```bash
# Get all registered platforms
pccsadmin get -u https://localhost:8081 -o platforms.json

# Get platforms whose certs are not available
pccsadmin get -s reg_na

# Get platforms from cache by FMSPC
pccsadmin get -s [00906EA10000,00906ED50000]

# Get all cached platforms
pccsadmin get -s []
```

**Options:**
- `-u <url>` - PCCS platforms API URL (default: https://localhost:8081/sgx/certification/v4/platforms)
- `-o <file>` - Output file name (default: platform_list.json)
- `-s <source>` - Source: `reg`, `reg_na`, or `[FMSPC1,FMSPC2,...]`
- `-t <token>` - Admin token (or set `PCCS_ADMIN_TOKEN` env var)
- `-k` - Skip TLS certificate verification

### put - Upload Collateral to PCCS

Upload platform collateral or appraisal policy to PCCS.

```bash
# Upload platform collateral
pccsadmin put -i collateral.json

# Upload appraisal policy
pccsadmin put -u https://localhost:8081/sgx/certification/v4/appraisalpolicy \
              -f 00906EA10000 -i policy.jwt -d
```

**Options:**
- `-u <url>` - PCCS API URL (default: https://localhost:8081/sgx/certification/v4/platformcollateral)
- `-i <file>` - Input file name (required)
- `-f <fmspc>` - FMSPC value (required for appraisal policy)
- `-d` - Make this the default policy for the FMSPC
- `-t <token>` - Admin token (or set `PCCS_ADMIN_TOKEN` env var)
- `-k` - Skip TLS certificate verification

### fetch - Fetch Collateral from Intel PCS

Fetch platform collateral from Intel's Provisioning Certificate Service.

```bash
# Fetch collateral for platforms
pccsadmin fetch -i platforms.json -o collateral.json -k YOUR_API_KEY

# Fetch only CRLs
pccsadmin fetch -c -k YOUR_API_KEY

# Fetch with early TCB update
pccsadmin fetch -t early -i platforms.json
```

**Options:**
- `-u <url>` - Intel PCS URL (default: https://api.trustedservices.intel.com/sgx/certification/v4/)
- `-i <file>` - Input platform list file (default: platform_list.json)
- `-o <file>` - Output collateral file (default: platform_collaterals.json)
- `-t <type>` - TCB update type: `standard`, `early`, or `all` (default: standard)
- `-k <key>` - Intel PCS API key (or set `INTEL_API_KEY` env var)
- `-c` - Retrieve only CRL

### collect - Collect Platform Data from CSV

Collect platform data from CSV files produced by Intel's PCK ID Retrieval Tool.

```bash
# Collect from current directory
pccsadmin collect -o platforms.json

# Collect from specific directory
pccsadmin collect -d ./platform_data -o platforms.json
```

**CSV Format:**
```
EncryptedPPID,PCE_ID,CPUSVN,PCE_ISVSVN,QE_ID
<data>...
```

**Options:**
- `-d <dir>` - Directory containing CSV files (default: ./)
- `-o <file>` - Output JSON file (default: platform_list.json)

### refresh - Refresh PCCS Cache

Request PCCS to refresh certificates or collateral in its cache.

```bash
# Refresh quote verification collateral
pccsadmin refresh

# Refresh all cached certificates
pccsadmin refresh -f all

# Refresh specific FMSPCs
pccsadmin refresh -f 00906EA10000,00906ED50000
```

**Options:**
- `-u <url>` - PCCS refresh API URL (default: https://localhost:8081/sgx/certification/v4/refresh)
- `-f <fmspc>` - FMSPC values: empty (default), `all`, or comma-separated list
- `-t <token>` - Admin token (or set `PCCS_ADMIN_TOKEN` env var)
- `-k` - Skip TLS certificate verification

## Environment Variables

- `INTEL_API_KEY` - Intel PCS API subscription key
- `PCCS_ADMIN_TOKEN` - PCCS admin authentication token

## Workflow Examples

### Setup PCCS in OFFLINE Mode

1. **Collect platform data from machines:**
   ```bash
   # Run Intel's PCK ID Retrieval Tool on each SGX machine to get CSV files
   # Copy all CSV files to a directory
   ```

2. **Collect CSV data into JSON:**
   ```bash
   pccsadmin collect -d ./platform_csvs -o platforms.json
   ```

3. **Fetch collateral from Intel PCS:**
   ```bash
   pccsadmin fetch -i platforms.json -o collateral.json -k YOUR_API_KEY
   ```

4. **Upload collateral to PCCS:**
   ```bash
   pccsadmin put -u https://pccs-server:8081/sgx/certification/v4/platformcollateral \
                 -i collateral.json -t YOUR_ADMIN_TOKEN
   ```

### Refresh PCCS Cache

```bash
# Refresh all collateral
pccsadmin refresh -u https://pccs-server:8081/sgx/certification/v4/refresh \
                  -t YOUR_ADMIN_TOKEN

# Refresh specific platforms
pccsadmin refresh -f 00906EA10000 -t YOUR_ADMIN_TOKEN
```

## Differences from Intel's Python Tool

This Go implementation provides the core functionality of Intel's PccsAdminTool with some differences:

### Implemented:
- `get` - Full support for fetching platforms from PCCS
- `put` - Full support for uploading collateral and policies
- `collect` - Full support for collecting CSV data
- `refresh` - Full support for triggering cache refresh
- `fetch` - Basic CRL fetch support

### Simplified:
- `fetch` command - Simplified implementation for CRL-only fetching
  - Full platform collateral fetch requires complex PCS interactions
  - Use Intel's original tool or manually construct collateral for complete fetch

### Advantages:
- **Single binary** - No Python dependencies
- **Cross-platform** - Works on Windows, Linux, macOS
- **Easy installation** - `go install` or run directly with `go run`
- **Lightweight** - No virtual environments or package managers needed

## License

This tool is part of the intel-dcapd project. See LICENSE for details.

## Related Tools

- [Intel SGX DCAP](https://github.com/intel/SGXDataCenterAttestationPrimitives) - Official Intel DCAP software
- [intel-dcapd](https://github.com/KarpelesLab/intel-dcapd) - Go PCCS replacement
