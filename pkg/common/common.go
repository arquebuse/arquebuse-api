package common

import (
	"golang.org/x/crypto/bcrypt"
	"os"
)

// Hash a secret with bcrypt
func HashSecret(secret string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

// Compare a clear text secret and a bcrypt hashed secret
func CompareSecretAndHash(secret string, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret))
}

// Check if a string is in a slice

// Check if a folder exists
func FolderExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}

// Check if a file exists
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
