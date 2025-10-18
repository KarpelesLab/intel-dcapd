package main

import (
	"fmt"
	"os"

	"github.com/KarpelesLab/intel-dcapd/version"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "get":
		if err := runGet(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "put":
		if err := runPut(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "fetch":
		if err := runFetch(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "collect":
		if err := runCollect(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "refresh":
		if err := runRefresh(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "version", "--version", "-v":
		fmt.Printf("pccsadmin version %s\n", version.Version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`PCCS Administrator Tool v%s

A command-line tool for managing Intel SGX DCAP PCCS (Provisioning Certificate Caching Service).

Usage: pccsadmin <command> [options]

Available Commands:
  get       Get platform registration data from PCCS
  put       Upload platform collateral or appraisal policy to PCCS
  fetch     Fetch platform collateral from Intel PCS
  collect   Collect platform data from CSV files
  refresh   Request PCCS to refresh cached data
  version   Show version information
  help      Show this help message

Use "pccsadmin <command> -h" for more information about a command.

Examples:
  # Get registered platforms from PCCS
  pccsadmin get -u https://localhost:8081 -o platforms.json

  # Fetch collateral from Intel PCS for platforms
  pccsadmin fetch -i platforms.json -o collateral.json

  # Upload collateral to PCCS
  pccsadmin put -u https://localhost:8081 -i collateral.json

  # Refresh PCCS cache
  pccsadmin refresh -u https://localhost:8081

`, version.Version)
}
