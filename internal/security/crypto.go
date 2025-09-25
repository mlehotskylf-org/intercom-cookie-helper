// Package security provides cryptographic primitives for secure cookie signing.
// This file contains HMAC-SHA256 functions used for cookie integrity protection.
package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
)

// hmacSignSHA256 computes HMAC-SHA256 of the message using the provided key.
// Used for cookie signing to detect tampering. Returns the MAC as bytes.
func hmacSignSHA256(key []byte, msg []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

// constantTimeEqual performs constant-time comparison of two byte slices.
// Prevents timing attacks when comparing MACs or other sensitive values.
// Returns true if slices are equal in both length and content.
func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
