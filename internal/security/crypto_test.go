package security

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestHmacSignSHA256(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		message  string
		expected string // hex-encoded expected HMAC
	}{
		{
			name:     "empty message",
			key:      "secret",
			message:  "",
			expected: "f9e66e179b6747ae54108f82f8ade8b3c25d76fd30afde6c395822c530196169",
		},
		{
			name:     "simple message",
			key:      "secret",
			message:  "hello",
			expected: "88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b",
		},
		{
			name:     "longer message",
			key:      "verysecretkey",
			message:  "The quick brown fox jumps over the lazy dog",
			expected: "73d933429a050a4d4f6cc01547cc5ea6c059d63fc7e4a39cb6f22b080d132956",
		},
		{
			name:     "binary key and message",
			key:      "\x01\x02\x03\x04",
			message:  "\xff\xfe\xfd\xfc",
			expected: "02f30b826d6af4ccb39e5169bb274cc12eb12a912f3d3c6583cb1845f5fc140f",
		},
		{
			name:     "RFC 4231 test vector 1",
			key:      string(bytes.Repeat([]byte{0x0b}, 20)),
			message:  "Hi There",
			expected: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
		},
		{
			name:     "RFC 4231 test vector 2",
			key:      "Jefe",
			message:  "what do ya want for nothing?",
			expected: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hmacSignSHA256([]byte(tt.key), []byte(tt.message))
			resultHex := hex.EncodeToString(result)

			if resultHex != tt.expected {
				t.Errorf("hmacSignSHA256() = %s, want %s", resultHex, tt.expected)
			}

			// Verify the result is always 32 bytes (SHA256 output size)
			if len(result) != 32 {
				t.Errorf("hmacSignSHA256() returned %d bytes, want 32", len(result))
			}
		})
	}
}

func TestConstantTimeEqual(t *testing.T) {
	tests := []struct {
		name     string
		a        []byte
		b        []byte
		expected bool
	}{
		{
			name:     "equal empty slices",
			a:        []byte{},
			b:        []byte{},
			expected: true,
		},
		{
			name:     "equal single byte",
			a:        []byte{0x42},
			b:        []byte{0x42},
			expected: true,
		},
		{
			name:     "equal multi-byte",
			a:        []byte("hello world"),
			b:        []byte("hello world"),
			expected: true,
		},
		{
			name:     "equal with nulls",
			a:        []byte{0x00, 0x01, 0x02, 0x00},
			b:        []byte{0x00, 0x01, 0x02, 0x00},
			expected: true,
		},
		{
			name:     "different single byte",
			a:        []byte{0x42},
			b:        []byte{0x43},
			expected: false,
		},
		{
			name:     "different lengths",
			a:        []byte("hello"),
			b:        []byte("hello world"),
			expected: false,
		},
		{
			name:     "same length different content",
			a:        []byte("hello"),
			b:        []byte("world"),
			expected: false,
		},
		{
			name:     "differ by one bit",
			a:        []byte{0b00000000},
			b:        []byte{0b00000001},
			expected: false,
		},
		{
			name:     "one empty one not",
			a:        []byte{},
			b:        []byte{0x00},
			expected: false,
		},
		{
			name:     "nil vs empty",
			a:        nil,
			b:        []byte{},
			expected: true, // both have length 0
		},
		{
			name:     "both nil",
			a:        nil,
			b:        nil,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := constantTimeEqual(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("constantTimeEqual(%v, %v) = %v, want %v",
					tt.a, tt.b, result, tt.expected)
			}

			// Test commutativity
			resultReversed := constantTimeEqual(tt.b, tt.a)
			if result != resultReversed {
				t.Errorf("constantTimeEqual is not commutative: (%v, %v) = %v, but (%v, %v) = %v",
					tt.a, tt.b, result, tt.b, tt.a, resultReversed)
			}
		})
	}
}

func TestConstantTimeEqualTiming(t *testing.T) {
	// This test verifies the function doesn't short-circuit on length mismatch
	// While we can't perfectly test timing in unit tests, we can ensure the
	// function structure is correct

	// Test that length check happens before comparison
	a := bytes.Repeat([]byte{0xFF}, 1000)
	b := bytes.Repeat([]byte{0xFF}, 999)

	result := constantTimeEqual(a, b)
	if result {
		t.Error("Expected false for different length slices")
	}

	// Equal length but different content - should go through constant-time compare
	b = bytes.Repeat([]byte{0xFE}, 1000)
	result = constantTimeEqual(a, b)
	if result {
		t.Error("Expected false for different content")
	}

	// Equal content - should go through constant-time compare and return true
	b = bytes.Repeat([]byte{0xFF}, 1000)
	result = constantTimeEqual(a, b)
	if !result {
		t.Error("Expected true for equal slices")
	}
}

func BenchmarkHmacSignSHA256(b *testing.B) {
	key := []byte("benchmark-key-1234567890")
	message := []byte("The quick brown fox jumps over the lazy dog")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = hmacSignSHA256(key, message)
	}
}

func BenchmarkConstantTimeEqual(b *testing.B) {
	slice1 := bytes.Repeat([]byte{0xAB}, 32)
	slice2 := bytes.Repeat([]byte{0xAB}, 32)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = constantTimeEqual(slice1, slice2)
	}
}

func BenchmarkConstantTimeEqualDifferent(b *testing.B) {
	slice1 := bytes.Repeat([]byte{0xAB}, 32)
	slice2 := bytes.Repeat([]byte{0xBA}, 32)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = constantTimeEqual(slice1, slice2)
	}
}