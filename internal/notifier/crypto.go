package notifier

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var secretKey []byte

func init() {
	keyPath := filepath.Join("plugins", ".secret.key")
	data, err := os.ReadFile(keyPath)
	if err == nil && len(data) == 64 {
		secretKey = make([]byte, 32)
		hex.Decode(secretKey, data)
		return
	}

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		hash := sha256.Sum256([]byte(fmt.Sprintf("%d-%d", os.Getpid(), os.Getppid())))
		copy(key, hash[:])
	}
	secretKey = key
	os.MkdirAll("plugins", 0755)
	os.WriteFile(keyPath, []byte(hex.EncodeToString(key)), 0600)
}

func EncryptSecret(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return plaintext, fmt.Errorf("cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return plaintext, fmt.Errorf("gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return plaintext, fmt.Errorf("nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return "enc:" + base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DecryptSecret(encoded string) string {
	if encoded == "" {
		return ""
	}
	if len(encoded) < 4 || encoded[:4] != "enc:" {
		return encoded
	}

	data, err := base64.StdEncoding.DecodeString(encoded[4:])
	if err != nil {
		return encoded
	}

	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return encoded
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return encoded
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return encoded
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return encoded
	}

	return string(plaintext)
}

func EncryptWebhooksJSON(wh map[string]string) (map[string]string, error) {
	encrypted := make(map[string]string)
	secretFields := []string{"discord", "slack", "telegram", "pushover", "custom"}

	for k, v := range wh {
		isSecret := false
		for _, f := range secretFields {
			if k == f {
				isSecret = true
				break
			}
		}
		if isSecret && v != "" {
			enc, err := EncryptSecret(v)
			if err != nil {
				return wh, err
			}
			encrypted[k] = enc
		} else {
			encrypted[k] = v
		}
	}
	if wh["custom_name"] != "" {
		encrypted["custom_name"] = wh["custom_name"]
	}
	return encrypted, nil
}

func LoadEncryptedWebhooksJSON(data []byte) map[string]string {
	var wh map[string]string
	if err := json.Unmarshal(data, &wh); err != nil {
		return nil
	}

	secretFields := []string{"discord", "slack", "telegram", "pushover", "custom"}
	for _, f := range secretFields {
		if v, ok := wh[f]; ok && v != "" {
			wh[f] = DecryptSecret(v)
		}
	}
	return wh
}
