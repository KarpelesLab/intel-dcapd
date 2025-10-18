package main

import (
	"crypto/sha512"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
)

// authMiddleware checks authentication tokens
type authMiddleware struct {
	userTokenHash  string
	adminTokenHash string
}

// newAuthMiddleware creates authentication middleware
func newAuthMiddleware() *authMiddleware {
	return &authMiddleware{
		userTokenHash:  os.Getenv("DCAPD_USER_TOKEN_SHA512"),
		adminTokenHash: os.Getenv("DCAPD_ADMIN_TOKEN_SHA512"),
	}
}

// validateUser checks user token from request header
func (a *authMiddleware) validateUser(next http.HandlerFunc) http.HandlerFunc {
	// If no user token hash is configured, allow all requests
	if a.userTokenHash == "" {
		return next
	}

	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("user-token")
		if token == "" {
			http.Error(w, "Unauthorized: missing user-token header", http.StatusUnauthorized)
			return
		}

		if !a.checkToken(token, a.userTokenHash) {
			http.Error(w, "Unauthorized: invalid user token", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

// validateAdmin checks admin token from request header
func (a *authMiddleware) validateAdmin(next http.HandlerFunc) http.HandlerFunc {
	// If no admin token hash is configured, allow all requests
	if a.adminTokenHash == "" {
		return next
	}

	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("admin-token")
		if token == "" {
			http.Error(w, "Unauthorized: missing admin-token header", http.StatusUnauthorized)
			return
		}

		if !a.checkToken(token, a.adminTokenHash) {
			http.Error(w, "Unauthorized: invalid admin token", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

// checkToken verifies if the token hash matches the expected hash
func (a *authMiddleware) checkToken(token, expectedHash string) bool {
	hash := sha512.Sum512([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])
	return strings.EqualFold(tokenHash, expectedHash)
}
