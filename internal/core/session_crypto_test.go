package core

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSessionCrypto_RoundTrip_MachineMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.json")
	data := []byte(`{"key":"value","nested":{"a":1}}`)

	if err := encryptSessionWithSource(path, data, KeySourceMachineID); err != nil {
		t.Fatalf("EncryptSession: %v", err)
	}

	got, err := DecryptSession(path)
	if err != nil {
		t.Fatalf("DecryptSession: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("round-trip mismatch: got %q, want %q", got, data)
	}
}

func TestSessionCrypto_MachineMode_DeterministicKey(t *testing.T) {
	salt := make([]byte, saltSize)

	key1, err := deriveKey(KeySourceMachineID, "", salt)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := deriveKey(KeySourceMachineID, "", salt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key1, key2) {
		t.Fatal("machine mode must produce same key on same machine across calls")
	}
	if len(key1) != 32 {
		t.Fatalf("key length = %d, want 32", len(key1))
	}
}

func TestSessionCrypto_PassphraseMode_DifferentPassphrasesYieldDifferentKeys(t *testing.T) {
	salt := make([]byte, saltSize)
	for i := range salt {
		salt[i] = byte(i)
	}

	key1, err := deriveKey(KeySourcePassphrase, "correct-horse", salt)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := deriveKey(KeySourcePassphrase, "battery-staple", salt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(key1, key2) {
		t.Fatal("different passphrases must produce different keys")
	}
}

func TestSessionCrypto_PassphraseMode_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.json")
	data := []byte(`{"token":"secret"}`)

	orig := readPassphrase
	t.Cleanup(func() { readPassphrase = orig })

	calls := 0
	readPassphrase = func(_ string) (string, error) {
		calls++
		return "s3cr3t-passphrase", nil
	}

	if err := encryptSessionWithSource(path, data, KeySourcePassphrase); err != nil {
		t.Fatalf("EncryptSession passphrase: %v", err)
	}

	got, err := DecryptSession(path)
	if err != nil {
		t.Fatalf("DecryptSession passphrase: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("passphrase round-trip mismatch: got %q, want %q", got, data)
	}
	if calls != 2 {
		t.Fatalf("expected readPassphrase called 2 times (once for encrypt, once for decrypt), got %d", calls)
	}
}

func TestSessionCrypto_PlaintextMigration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "telegram_session.json")
	plaintext := []byte("{}\n")

	// Write a plaintext file (simulating a pre-encryption session).
	if err := os.WriteFile(path, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}

	// Capture log output.
	var logBuf strings.Builder
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	got, err := DecryptSession(path)
	if err != nil {
		t.Fatalf("DecryptSession on plaintext: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("migration returned wrong data: got %q, want %q", got, plaintext)
	}

	// File must now be encrypted.
	raw, _ := os.ReadFile(path)
	if !isEncryptedSession(raw) {
		t.Fatal("plaintext file was not migrated to encrypted format")
	}

	if !strings.Contains(logBuf.String(), "migrated to encrypted storage") {
		t.Fatalf("expected migration log message, got: %q", logBuf.String())
	}
}

func TestSessionCrypto_CiphertextDoesNotContainPlaintext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.json")
	data := []byte(`{"secret":"my-very-secret-token"}`)

	if err := encryptSessionWithSource(path, data, KeySourceMachineID); err != nil {
		t.Fatal(err)
	}

	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, data) {
		t.Fatal("encrypted file must not contain plaintext data")
	}
	if bytes.Contains(raw, []byte("secret")) {
		t.Fatal("encrypted file must not contain recognisable plaintext tokens")
	}
}

func TestSessionCrypto_BothMode_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.json")
	data := []byte(`{"combined":"mode"}`)

	orig := readPassphrase
	t.Cleanup(func() { readPassphrase = orig })
	readPassphrase = func(_ string) (string, error) { return "hunter2", nil }

	if err := encryptSessionWithSource(path, data, KeySourceBoth); err != nil {
		t.Fatalf("EncryptSession both: %v", err)
	}
	got, err := DecryptSession(path)
	if err != nil {
		t.Fatalf("DecryptSession both: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("both-mode round-trip mismatch: got %q, want %q", got, data)
	}
}
