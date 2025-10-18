package maintenance

import (
	"log"
	"time"

	"github.com/KarpelesLab/intel-dcapd/cache"
	"github.com/KarpelesLab/intel-dcapd/pcs"
)

// Start begins the background maintenance goroutine
func Start(db *cache.DB, pcsClient *pcs.Client) {
	ticker := time.NewTicker(24 * time.Hour) // Run daily
	defer ticker.Stop()

	// Run initial refresh after 1 minute
	time.AfterFunc(1*time.Minute, func() {
		refresh(db, pcsClient)
	})

	for range ticker.C {
		refresh(db, pcsClient)
	}
}

// refresh performs periodic cache refresh
func refresh(db *cache.DB, pcsClient *pcs.Client) {
	log.Println("Starting scheduled cache refresh...")

	// Refresh TCB info for all known FMSPCs
	refreshTCBInfo(db, pcsClient)

	// Refresh enclave identities
	refreshIdentities(db, pcsClient)

	// Refresh CRLs
	refreshCRLs(db, pcsClient)

	log.Println("Scheduled cache refresh complete")
}

// refreshTCBInfo refreshes TCB information for all cached platforms
func refreshTCBInfo(db *cache.DB, pcsClient *pcs.Client) {
	fmspcs := db.GetAllFMSPCs()
	if len(fmspcs) == 0 {
		log.Println("No FMSPCs to refresh")
		return
	}

	log.Printf("Refreshing TCB info for %d FMSPCs", len(fmspcs))

	for _, fmspc := range fmspcs {
		// Refresh both standard and early update types for SGX
		for _, updateType := range []string{cache.UpdateTypeStandard, cache.UpdateTypeEarly} {
			resp, err := pcsClient.GetTCBInfoForSGX(fmspc, updateType)
			if err != nil {
				log.Printf("Failed to refresh TCB info for FMSPC %s (%s): %v", fmspc, updateType, err)
				continue
			}

			if resp.StatusCode == 200 {
				if err := db.PutTCBInfo(cache.ProdTypeSGX, fmspc, "4", updateType, resp.Body); err != nil {
					log.Printf("Failed to store TCB info for FMSPC %s (%s): %v", fmspc, updateType, err)
				} else {
					log.Printf("Refreshed TCB info for FMSPC %s (%s)", fmspc, updateType)
				}
			}
		}
	}
}

// refreshIdentities refreshes enclave identities
func refreshIdentities(db *cache.DB, pcsClient *pcs.Client) {
	log.Println("Refreshing enclave identities")

	identities := []string{cache.IdentityQE, cache.IdentityQVE, cache.IdentityTDQE}
	updateTypes := []string{cache.UpdateTypeStandard, cache.UpdateTypeEarly}

	for _, id := range identities {
		for _, updateType := range updateTypes {
			resp, err := pcsClient.GetEnclaveIdentity(id, updateType)
			if err != nil {
				log.Printf("Failed to refresh identity %s (%s): %v", id, updateType, err)
				continue
			}

			if resp.StatusCode == 200 {
				if err := db.PutIdentity(id, "4", updateType, resp.Body); err != nil {
					log.Printf("Failed to store identity %s (%s): %v", id, updateType, err)
				} else {
					log.Printf("Refreshed identity %s (%s)", id, updateType)
				}
			}
		}
	}
}

// refreshCRLs refreshes certificate revocation lists
func refreshCRLs(db *cache.DB, pcsClient *pcs.Client) {
	log.Println("Refreshing CRLs")

	cas := []string{cache.CAProcessor, cache.CAPlatform}

	for _, ca := range cas {
		resp, err := pcsClient.GetPCKCRL(ca)
		if err != nil {
			log.Printf("Failed to refresh CRL for CA %s: %v", ca, err)
			continue
		}

		if resp.StatusCode == 200 {
			if err := db.PutCRL(ca, resp.Body); err != nil {
				log.Printf("Failed to store CRL for CA %s: %v", ca, err)
			} else {
				log.Printf("Refreshed CRL for CA %s", ca)
			}
		}
	}
}
