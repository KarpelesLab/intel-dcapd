package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func runCollect(args []string) error {
	fs := flag.NewFlagSet("collect", flag.ExitOnError)
	directory := fs.String("d", "./", "The directory which stores platform CSV files")
	outputFile := fs.String("o", "platform_list.json", "The output JSON file name")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: pccsadmin collect [options]

Collect platform data from CSV files into a single JSON file.

The CSV files should be in the format produced by Intel's PCK ID Retrieval Tool:
EncryptedPPID,PCE_ID,CPUSVN,PCE_ISVSVN,QE_ID

Options:
  -d <dir>     The directory which stores the platform CSV files
               Default: ./
  -o <file>    The output JSON file name
               Default: platform_list.json

Example:
  pccsadmin collect -d ./platform_data -o platforms.json
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Find all CSV files in the directory
	csvFiles, err := filepath.Glob(filepath.Join(*directory, "*.csv"))
	if err != nil {
		return fmt.Errorf("failed to search for CSV files: %w", err)
	}

	if len(csvFiles) == 0 {
		return fmt.Errorf("no CSV files found in directory: %s", *directory)
	}

	fmt.Printf("Found %d CSV file(s)\n", len(csvFiles))

	var platforms []map[string]string

	// Process each CSV file
	for _, csvFile := range csvFiles {
		fmt.Printf("Processing: %s\n", csvFile)

		file, err := os.Open(csvFile)
		if err != nil {
			fmt.Printf("Warning: Failed to open %s: %v\n", csvFile, err)
			continue
		}

		reader := csv.NewReader(file)

		// Read header
		header, err := reader.Read()
		if err != nil {
			file.Close()
			fmt.Printf("Warning: Failed to read header from %s: %v\n", csvFile, err)
			continue
		}

		// Normalize header names
		for i := range header {
			header[i] = strings.TrimSpace(header[i])
		}

		// Read data rows
		lineNum := 1
		for {
			record, err := reader.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				fmt.Printf("Warning: Error reading line %d from %s: %v\n", lineNum, csvFile, err)
				lineNum++
				continue
			}

			// Build platform object from CSV row
			platform := make(map[string]string)
			for i, value := range record {
				if i < len(header) {
					key := header[i]
					// Map CSV column names to JSON field names
					switch key {
					case "EncryptedPPID", "Encrypted PPID", "enc_ppid":
						platform["enc_ppid"] = strings.TrimSpace(value)
					case "PCE_ID", "PCEID", "pce_id":
						platform["pce_id"] = strings.TrimSpace(value)
					case "CPUSVN", "cpu_svn":
						platform["cpu_svn"] = strings.TrimSpace(value)
					case "PCE_ISVSVN", "PCESVN", "pce_svn":
						platform["pce_svn"] = strings.TrimSpace(value)
					case "QE_ID", "QEID", "qe_id":
						platform["qe_id"] = strings.TrimSpace(value)
					case "PlatformManifest", "platform_manifest":
						platform["platform_manifest"] = strings.TrimSpace(value)
					default:
						// Store other fields as-is
						if value != "" {
							platform[strings.ToLower(key)] = strings.TrimSpace(value)
						}
					}
				}
			}

			// Only add platform if it has required fields
			if platform["qe_id"] != "" && platform["pce_id"] != "" {
				platforms = append(platforms, platform)
			}

			lineNum++
		}

		file.Close()
	}

	if len(platforms) == 0 {
		return fmt.Errorf("no valid platform data found in CSV files")
	}

	fmt.Printf("Collected %d platform(s)\n", len(platforms))

	// Write JSON output
	output, err := json.MarshalIndent(platforms, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := os.WriteFile(*outputFile, output, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	fmt.Printf("Successfully saved platform list to: %s\n", *outputFile)
	return nil
}
