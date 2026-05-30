package core

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// SessionKeySource controls how the AES-256-GCM key for session files is derived.
type SessionKeySource string

const (
	KeySourceMachineID  SessionKeySource = "machine"    // derived from machine ID only (default, transparent)
	KeySourcePassphrase SessionKeySource = "passphrase" // derived from user passphrase via PBKDF2
	KeySourceBoth       SessionKeySource = "both"       // PBKDF2(passphrase + machineID)
)

// sessionFileHeader is the binary layout prepended to every encrypted session file.
//
//	[4]  magic:      0x50 0x48 0x41 0x43 ("PHAC")
//	[1]  version:    0x01
//	[1]  key_source: 0x00=machine, 0x01=passphrase, 0x02=both
//	[32] salt:       random bytes (zeros for machine mode)
//	[12] nonce:      GCM nonce
const (
	sessionMagic      = "PHAC"
	sessionVersion    = byte(1)
	saltSize          = 32
	nonceSize         = 12
	sessionHeaderSize = 4 + 1 + 1 + saltSize + nonceSize
	pbkdf2Iterations  = 100_000
	pbkdf2KeyLen      = 32
)

var keySourceByte = map[SessionKeySource]byte{
	KeySourceMachineID:  0x00,
	KeySourcePassphrase: 0x01,
	KeySourceBoth:       0x02,
}

var byteKeySource = map[byte]SessionKeySource{
	0x00: KeySourceMachineID,
	0x01: KeySourcePassphrase,
	0x02: KeySourceBoth,
}

// readPassphrase is overridable in tests.
var readPassphrase = func(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	reader := bufio.NewReader(os.Stdin)
	pass, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(pass, "\r\n"), nil
}

// EncryptSession encrypts data with AES-256-GCM and writes the ciphertext to path.
// The key source is resolved from the SESSION_KEY_SOURCE env var (default: machine).
func EncryptSession(path string, data []byte) error {
	src := resolveKeySource()
	return encryptSessionWithSource(path, data, src)
}

func encryptSessionWithSource(path string, data []byte, src SessionKeySource) error {
	salt := make([]byte, saltSize)
	if src != KeySourceMachineID {
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return fmt.Errorf("generate salt: %w", err)
		}
	}

	passphrase := ""
	if src == KeySourcePassphrase || src == KeySourceBoth {
		var err error
		passphrase, err = readPassphrase("Session passphrase: ")
		if err != nil {
			return fmt.Errorf("read passphrase: %w", err)
		}
	}

	key, err := deriveKey(src, passphrase, salt)
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)

	// Assemble: magic + version + key_source + salt + nonce + ciphertext
	out := make([]byte, 0, sessionHeaderSize+len(ciphertext))
	out = append(out, []byte(sessionMagic)...)
	out = append(out, sessionVersion)
	out = append(out, keySourceByte[src])
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)

	if err := os.MkdirAll(dirOf(path), 0o700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}
	return os.WriteFile(path, out, 0o600)
}

// DecryptSession reads and decrypts the session file at path.
// If a plaintext file is detected it is automatically migrated to encrypted storage.
func DecryptSession(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if !isEncryptedSession(raw) {
		// Plaintext detected — migrate.
		if encErr := encryptSessionWithSource(path, raw, resolveKeySource()); encErr != nil {
			return nil, fmt.Errorf("migrate plaintext session: %w", encErr)
		}
		log.Println("Session file migrated to encrypted storage.")
		return raw, nil
	}

	return decryptSessionBytes(raw)
}

func decryptSessionBytes(raw []byte) ([]byte, error) {
	if len(raw) < sessionHeaderSize {
		return nil, errors.New("session file too short")
	}

	src, ok := byteKeySource[raw[5]]
	if !ok {
		return nil, errors.New("unknown session key source byte")
	}

	salt := raw[6 : 6+saltSize]
	nonce := raw[6+saltSize : 6+saltSize+nonceSize]
	ciphertext := raw[sessionHeaderSize:]

	passphrase := ""
	if src == KeySourcePassphrase || src == KeySourceBoth {
		var err error
		passphrase, err = readPassphrase("Session passphrase: ")
		if err != nil {
			return nil, fmt.Errorf("read passphrase: %w", err)
		}
	}

	key, err := deriveKey(src, passphrase, salt)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt session: %w", err)
	}
	return plaintext, nil
}

// isEncryptedSession returns true if raw begins with the "PHAC" magic and has the expected header.
func isEncryptedSession(raw []byte) bool {
	return len(raw) >= sessionHeaderSize && string(raw[:4]) == sessionMagic && raw[4] == sessionVersion
}

// deriveKey produces a 32-byte AES key for the given source.
func deriveKey(src SessionKeySource, passphrase string, salt []byte) ([]byte, error) {
	switch src {
	case KeySourceMachineID:
		machineID, err := getMachineID()
		if err != nil {
			// Fall back to a stable placeholder so sessions still work even if
			// machine-id is unavailable (e.g. containers without /etc/machine-id).
			machineID = "fallback-machine-id"
		}
		h := sha256.Sum256([]byte(machineID))
		return h[:], nil

	case KeySourcePassphrase:
		return pbkdf2.Key([]byte(passphrase), salt, pbkdf2Iterations, pbkdf2KeyLen, sha256.New), nil

	case KeySourceBoth:
		machineID, err := getMachineID()
		if err != nil {
			machineID = "fallback-machine-id"
		}
		combined := []byte(passphrase + machineID)
		return pbkdf2.Key(combined, salt, pbkdf2Iterations, pbkdf2KeyLen, sha256.New), nil

	default:
		return nil, fmt.Errorf("unknown key source: %q", src)
	}
}

// getMachineID returns a stable machine-unique identifier.
func getMachineID() (string, error) {
	switch runtime.GOOS {
	case "linux":
		return getMachineIDLinux()
	case "darwin":
		return getMachineIDDarwin()
	case "windows":
		return getMachineIDWindows()
	default:
		return getMachineIDLinux()
	}
}

func getMachineIDLinux() (string, error) {
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		data, err := os.ReadFile(path)
		if err == nil {
			return strings.TrimSpace(string(data)), nil
		}
	}
	return "", errors.New("machine-id not found")
}

func getMachineIDDarwin() (string, error) {
	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return "", fmt.Errorf("ioreg: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "IOPlatformUUID") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return strings.Trim(strings.TrimSpace(parts[1]), "\" "), nil
			}
		}
	}
	return "", errors.New("IOPlatformUUID not found")
}

func getMachineIDWindows() (string, error) {
	out, err := exec.Command("reg", "query",
		`HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid").Output()
	if err != nil {
		return "", fmt.Errorf("reg query: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "MachineGuid") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				return fields[len(fields)-1], nil
			}
		}
	}
	return "", errors.New("MachineGuid not found in registry")
}

// resolveKeySource reads SESSION_KEY_SOURCE from the environment.
func resolveKeySource() SessionKeySource {
	src := strings.TrimSpace(os.Getenv("SESSION_KEY_SOURCE"))
	switch SessionKeySource(src) {
	case KeySourcePassphrase, KeySourceBoth:
		return SessionKeySource(src)
	default:
		return KeySourceMachineID
	}
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i]
		}
	}
	return "."
}
