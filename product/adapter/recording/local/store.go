// Package local stores encrypted recording segments for standalone Product
// deployments. Logical references never reveal host paths or encryption keys.
package local

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/shell-echo/sandbox-runtime/product"
)

type Store struct {
	directory string
	masterKey [32]byte
	random    io.Reader
}

func New(root string, masterKey []byte) (*Store, error) {
	if root == "" || len(masterKey) != 32 {
		return nil, product.ErrInvalid
	}
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(root, 0o700); err != nil {
			return nil, product.ErrStoreUnavailable
		}
		info, err = os.Lstat(root)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, product.ErrInvalid
	}
	directory := filepath.Join(root, "recordings")
	if err := ensurePrivateDirectory(directory); err != nil {
		return nil, product.ErrStoreUnavailable
	}
	store := &Store{directory: directory, random: rand.Reader}
	copy(store.masterKey[:], masterKey)
	return store, nil
}

func (s *Store) CreateKeyReference(ctx context.Context, tenantID, recordingID string) (string, error) {
	if s == nil || ctx == nil || !validID(tenantID) || !validID(recordingID) {
		return "", product.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	randomValue := make([]byte, 32)
	if _, err := io.ReadFull(s.random, randomValue); err != nil {
		return "", product.ErrStoreUnavailable
	}
	mac := hmac.New(sha256.New, s.masterKey[:])
	_, _ = mac.Write(scopeEncoding("sandbox-runtime/local-recording-key/v2", tenantID, recordingID))
	_, _ = mac.Write(randomValue)
	payload := append(randomValue, mac.Sum(nil)...)
	return "rkey2:" + base64.RawURLEncoding.EncodeToString(payload), nil
}

func (s *Store) PutSegment(ctx context.Context, tenantID, recordingID, keyReference string, sequence int64, payload []byte) (string, error) {
	if s == nil || ctx == nil || !validID(tenantID) || !validID(recordingID) || !s.validKeyReference(tenantID, recordingID, keyReference) || sequence < 1 || sequence > product.MaxRecordingSegments || len(payload) < 1 || len(payload) > product.MaxRecordingSegmentBytes {
		return "", product.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	reference := fmt.Sprintf("recording:%s:%d", recordingID, sequence)
	filePath, ok := s.segmentPath(tenantID, recordingID, reference)
	if !ok {
		return "", product.ErrInvalid
	}
	aead, err := s.aead(keyReference)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(s.random, nonce); err != nil {
		return "", product.ErrStoreUnavailable
	}
	document := aead.Seal(nonce, nonce, payload, segmentAAD(tenantID, recordingID, keyReference, sequence))
	if err := ensurePrivateDirectory(filepath.Dir(filePath)); err != nil {
		return "", product.ErrStoreUnavailable
	}
	fd, err := unix.Open(filePath, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			existing, readErr := s.ReadSegment(ctx, tenantID, recordingID, keyReference, sequence, reference)
			if readErr == nil && bytes.Equal(existing, payload) {
				return reference, nil
			}
			return "", product.ErrVersionConflict
		}
		return "", product.ErrStoreUnavailable
	}
	file := os.NewFile(uintptr(fd), "encrypted-recording-segment")
	defer file.Close()
	if _, err := file.Write(document); err != nil || file.Sync() != nil {
		_ = os.Remove(filePath)
		return "", product.ErrStoreUnavailable
	}
	return reference, nil
}

func (s *Store) ReadSegment(ctx context.Context, tenantID, recordingID, keyReference string, sequence int64, reference string) ([]byte, error) {
	if s == nil || ctx == nil || !validID(tenantID) || reference != fmt.Sprintf("recording:%s:%d", recordingID, sequence) || !s.validKeyReference(tenantID, recordingID, keyReference) {
		return nil, product.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	filePath, ok := s.segmentPath(tenantID, recordingID, reference)
	if !ok {
		return nil, product.ErrInvalid
	}
	fd, err := unix.Open(filePath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, product.ErrStoreUnavailable
	}
	file := os.NewFile(uintptr(fd), "encrypted-recording-segment")
	defer file.Close()
	document, err := io.ReadAll(io.LimitReader(file, product.MaxRecordingSegmentBytes+64))
	if err != nil {
		return nil, product.ErrStoreUnavailable
	}
	aead, err := s.aead(keyReference)
	if err != nil || len(document) <= aead.NonceSize() {
		return nil, product.ErrStoreUnavailable
	}
	plaintext, err := aead.Open(nil, document[:aead.NonceSize()], document[aead.NonceSize():], segmentAAD(tenantID, recordingID, keyReference, sequence))
	if err != nil || len(plaintext) > product.MaxRecordingSegmentBytes {
		return nil, product.ErrStoreUnavailable
	}
	return plaintext, nil
}

func (s *Store) DeleteSegments(ctx context.Context, tenantID, recordingID, keyReference string, references []string) error {
	if s == nil || ctx == nil || !validID(tenantID) || !validID(recordingID) || !s.validKeyReference(tenantID, recordingID, keyReference) || len(references) > product.MaxRecordingSegments {
		return product.ErrInvalid
	}
	for _, reference := range references {
		if err := ctx.Err(); err != nil {
			return err
		}
		filePath, ok := s.segmentPath(tenantID, recordingID, reference)
		if !ok {
			return product.ErrInvalid
		}
		if err := os.Remove(filePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return product.ErrStoreUnavailable
		}
	}
	return nil
}

func (s *Store) DeleteRecording(ctx context.Context, tenantID, recordingID, keyReference string) error {
	if s == nil || ctx == nil || !validID(tenantID) || !validID(recordingID) || !s.validKeyReference(tenantID, recordingID, keyReference) {
		return product.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	directory := s.recordingDirectory(tenantID, recordingID)
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return product.ErrStoreUnavailable
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return product.ErrStoreUnavailable
	}
	if len(entries) > product.MaxRecordingSegments {
		return product.ErrStoreUnavailable
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return product.ErrStoreUnavailable
		}
		if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return product.ErrStoreUnavailable
		}
	}
	if err := os.Remove(directory); err != nil && !errors.Is(err, os.ErrNotExist) {
		return product.ErrStoreUnavailable
	}
	return nil
}

func ensurePrivateDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return product.ErrStoreUnavailable
	}
	return nil
}

func (s *Store) aead(keyReference string) (cipher.AEAD, error) {
	mac := hmac.New(sha256.New, s.masterKey[:])
	_, _ = mac.Write([]byte(keyReference))
	key := mac.Sum(nil)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, product.ErrStoreUnavailable
	}
	return cipher.NewGCM(block)
}

func (s *Store) segmentPath(tenantID, recordingID, reference string) (string, bool) {
	parts := strings.Split(reference, ":")
	if !validID(tenantID) || !validID(recordingID) || len(parts) != 3 || parts[0] != "recording" || parts[1] != recordingID || !validID(parts[1]) || parts[2] == "" || strings.ContainsAny(reference, "/\\\x00") {
		return "", false
	}
	sum := sha256.Sum256([]byte(reference))
	return filepath.Join(s.recordingDirectory(tenantID, recordingID), hex.EncodeToString(sum[:])+".segment"), true
}

func (s *Store) recordingDirectory(tenantID, recordingID string) string {
	sum := sha256.Sum256(scopeEncoding("sandbox-runtime/local-recording-directory/v2", tenantID, recordingID))
	return filepath.Join(s.directory, hex.EncodeToString(sum[:]))
}

func segmentAAD(tenantID, recordingID, keyReference string, sequence int64) []byte {
	result := scopeEncoding("sandbox-runtime/local-recording-segment-aad/v2", tenantID, recordingID, keyReference)
	buffer := make([]byte, 8)
	binary.BigEndian.PutUint64(buffer, uint64(sequence))
	return append(result, buffer...)
}

func scopeEncoding(domain string, values ...string) []byte {
	result := make([]byte, 0, len(domain)+len(values)*16)
	result = appendLengthPrefixed(result, domain)
	for _, value := range values {
		result = appendLengthPrefixed(result, value)
	}
	return result
}

func appendLengthPrefixed(destination []byte, value string) []byte {
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(value)))
	destination = append(destination, length...)
	return append(destination, value...)
}

func (s *Store) validKeyReference(tenantID, recordingID, value string) bool {
	if s == nil || !validID(tenantID) || !validID(recordingID) || !strings.HasPrefix(value, "rkey2:") || len(value) != len("rkey2:")+86 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, "rkey2:"))
	if err != nil || len(payload) != 64 {
		return false
	}
	mac := hmac.New(sha256.New, s.masterKey[:])
	_, _ = mac.Write(scopeEncoding("sandbox-runtime/local-recording-key/v2", tenantID, recordingID))
	_, _ = mac.Write(payload[:32])
	return hmac.Equal(payload[32:], mac.Sum(nil))
}

func validID(value string) bool {
	if len(value) < 1 || len(value) > 200 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') && !(character >= '0' && character <= '9') && !strings.ContainsRune("._:-", character) {
			return false
		}
	}
	return true
}

var _ product.RecordingContentStore = (*Store)(nil)
