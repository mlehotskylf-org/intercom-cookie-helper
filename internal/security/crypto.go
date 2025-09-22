package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
)

// hmacSignSHA256 computes HMAC-SHA256 of the message using the provided key
func hmacSignSHA256(key []byte, msg []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

// constantTimeEqual performs constant-time comparison of two byte slices
// Returns true if slices are equal in both length and content
func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}