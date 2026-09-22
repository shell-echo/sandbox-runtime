// Package kms stores tenant-bound recording segments with one random data
// encryption key per recording. The data key is wrapped and unwrapped only
// through an opaque KMS/HSM provider; the configured KMS reference is never
// persisted in handles or segment files.
package kms

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/product"
)

const (
	contentAlgorithm       = "aes-256-gcm"
	storeDirectoryName     = "recordings-kms-v1"
	maxWrappedDataKeyBytes = 64 << 10
	maxSegmentDocumentSize = 128 << 10
)

type Store struct {
	directory string
	provider  *secretref.BoundEnvelopeKeyProvider
	bindings  *secretref.EnvelopeBindingSet
	random    io.Reader
}

func New(root string, provider secretref.EnvelopeKeyProvider, bindings *secretref.EnvelopeBindingSet) (*Store, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || provider == nil || bindings == nil {
		return nil, product.ErrInvalid
	}
	purpose, role, ok := bindings.Scope()
	if !ok || purpose != secretref.PurposeRecordingEnvelopeKey || role != secretref.RoleProduct {
		return nil, product.ErrInvalid
	}
	if err := ensureStoreRoot(root); err != nil {
		return nil, err
	}
	directory := filepath.Join(root, storeDirectoryName)
	if err := ensurePrivateDirectory(directory); err != nil {
		return nil, err
	}
	bound, err := secretref.NewBoundEnvelopeKeyProvider(provider)
	if err != nil {
		return nil, product.ErrInvalid
	}
	return &Store{directory: directory, provider: bound, bindings: bindings, random: rand.Reader}, nil
}

func (s *Store) CreateKeyReference(ctx context.Context, tenantID, recordingID string) (string, error) {
	if s == nil || s.provider == nil || s.bindings == nil || ctx == nil || !validID(tenantID) || !validID(recordingID) {
		return "", product.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	binding, err := s.bindings.BindingForSeal(tenantID)
	if err != nil {
		return "", providerError(err)
	}
	dataKey := make([]byte, 32)
	if _, err := io.ReadFull(s.random, dataKey); err != nil {
		clear(dataKey)
		return "", product.ErrStoreUnavailable
	}
	defer clear(dataKey)
	envelope, err := s.provider.SealEnvelope(ctx, binding, dataKey, wrapAAD(tenantID, recordingID, binding))
	if err != nil {
		return "", providerError(err)
	}
	defer clear(envelope.Ciphertext)
	if len(envelope.Ciphertext) > maxWrappedDataKeyBytes {
		return "", product.ErrStoreUnavailable
	}
	handle := keyHandleFromEnvelope(envelope)
	defer clear(handle.WrappedDataKey)
	return encodeKeyHandle(handle)
}

func (s *Store) PutSegment(ctx context.Context, tenantID, recordingID, keyReference string, sequence int64, payload []byte) (string, error) {
	if s == nil || ctx == nil || !validID(tenantID) || !validID(recordingID) || sequence < 1 || sequence > product.MaxRecordingSegments || len(payload) < 1 || len(payload) > product.MaxRecordingSegmentBytes {
		return "", product.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	handle, binding, err := s.resolveHandleForOpen(tenantID, keyReference)
	if err != nil {
		return "", err
	}
	dataKey, err := s.provider.OpenEnvelope(ctx, binding, handle.envelope(), wrapAAD(tenantID, recordingID, binding))
	if err != nil {
		return "", providerError(err)
	}
	defer clear(dataKey)
	if len(dataKey) != 32 {
		return "", product.ErrStoreUnavailable
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return "", product.ErrStoreUnavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", product.ErrStoreUnavailable
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(s.random, nonce); err != nil {
		return "", product.ErrStoreUnavailable
	}
	reference := fmt.Sprintf("recording:%s:%d", recordingID, sequence)
	document := segmentDocument{
		Schema:           segmentSchema,
		FormatVersion:    1,
		BindingDigest:    binding.Digest(),
		KMSKeyVersion:    binding.Version,
		ProviderKeyID:    binding.KeyID,
		WrapAlgorithm:    secretref.EnvelopeAlgorithmV1,
		ContentAlgorithm: contentAlgorithm,
		Nonce:            nonce,
		Ciphertext:       aead.Seal(nil, nonce, payload, segmentAAD(tenantID, recordingID, reference, sequence, binding)),
	}
	encoded, err := encodeSegmentDocument(document)
	if err != nil {
		return "", product.ErrStoreUnavailable
	}
	defer clear(encoded)
	filePath, ok := s.segmentPath(tenantID, recordingID, reference)
	if !ok {
		return "", product.ErrInvalid
	}
	if err := ensurePrivateDirectory(filepath.Dir(filePath)); err != nil {
		return "", err
	}
	fd, err := unix.Open(filePath, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			existing, readErr := s.ReadSegment(ctx, tenantID, recordingID, keyReference, sequence, reference)
			if readErr != nil {
				return "", readErr
			}
			defer clear(existing)
			if bytes.Equal(existing, payload) {
				return reference, nil
			}
			return "", product.ErrVersionConflict
		}
		return "", product.ErrStoreUnavailable
	}
	file := os.NewFile(uintptr(fd), "kms-recording-segment")
	defer file.Close()
	if err := writeFull(ctx, file, encoded); err != nil || file.Sync() != nil {
		_ = os.Remove(filePath)
		return "", product.ErrStoreUnavailable
	}
	return reference, nil
}

func (s *Store) ReadSegment(ctx context.Context, tenantID, recordingID, keyReference string, sequence int64, reference string) ([]byte, error) {
	if s == nil || ctx == nil || !validID(tenantID) || !validID(recordingID) || sequence < 1 || sequence > product.MaxRecordingSegments || reference != fmt.Sprintf("recording:%s:%d", recordingID, sequence) {
		return nil, product.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	handle, binding, err := s.resolveHandleForOpen(tenantID, keyReference)
	if err != nil {
		return nil, err
	}
	filePath, ok := s.segmentPath(tenantID, recordingID, reference)
	if !ok {
		return nil, product.ErrInvalid
	}
	exists, err := privateDirectoryState(filepath.Dir(filePath))
	if err != nil || !exists {
		return nil, product.ErrStoreUnavailable
	}
	documentBytes, err := readPrivateFile(ctx, filePath, maxSegmentDocumentSize)
	if err != nil {
		return nil, err
	}
	defer clear(documentBytes)
	document, err := decodeSegmentDocument(documentBytes)
	if err != nil || !document.matches(binding) {
		return nil, product.ErrStoreUnavailable
	}
	dataKey, err := s.provider.OpenEnvelope(ctx, binding, handle.envelope(), wrapAAD(tenantID, recordingID, binding))
	if err != nil {
		return nil, providerError(err)
	}
	defer clear(dataKey)
	if len(dataKey) != 32 {
		return nil, product.ErrStoreUnavailable
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, product.ErrStoreUnavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(document.Nonce) != aead.NonceSize() || len(document.Ciphertext) < aead.Overhead() {
		return nil, product.ErrStoreUnavailable
	}
	plaintext, err := aead.Open(nil, document.Nonce, document.Ciphertext, segmentAAD(tenantID, recordingID, reference, sequence, binding))
	if err != nil || len(plaintext) < 1 || len(plaintext) > product.MaxRecordingSegmentBytes {
		clear(plaintext)
		return nil, product.ErrStoreUnavailable
	}
	return plaintext, nil
}

func (s *Store) DeleteSegments(ctx context.Context, tenantID, recordingID, keyReference string, references []string) error {
	if s == nil || ctx == nil || !validID(tenantID) || !validID(recordingID) || len(references) > product.MaxRecordingSegments {
		return product.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.validateHandleForCleanup(tenantID, keyReference); err != nil {
		return err
	}
	paths := make([]string, 0, len(references))
	for _, reference := range references {
		filePath, ok := s.segmentPath(tenantID, recordingID, reference)
		if !ok {
			return product.ErrInvalid
		}
		paths = append(paths, filePath)
	}
	if len(paths) == 0 {
		return nil
	}
	exists, err := privateDirectoryState(filepath.Dir(paths[0]))
	if err != nil {
		return product.ErrStoreUnavailable
	}
	if !exists {
		return nil
	}
	for _, filePath := range paths {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := os.Remove(filePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return product.ErrStoreUnavailable
		}
	}
	return nil
}

func (s *Store) DeleteRecording(ctx context.Context, tenantID, recordingID, keyReference string) error {
	if s == nil || ctx == nil || !validID(tenantID) || !validID(recordingID) {
		return product.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.validateHandleForCleanup(tenantID, keyReference); err != nil {
		return err
	}
	directory := s.recordingDirectory(tenantID, recordingID)
	exists, err := privateDirectoryState(directory)
	if err != nil {
		return product.ErrStoreUnavailable
	}
	if !exists {
		return nil
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) > product.MaxRecordingSegments {
		return product.ErrStoreUnavailable
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !validSegmentFilename(entry.Name()) {
			return product.ErrStoreUnavailable
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
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

func (s *Store) resolveHandleForOpen(tenantID, keyReference string) (keyHandle, secretref.Binding, error) {
	handle, err := decodeKeyHandle(keyReference)
	if err != nil {
		return keyHandle{}, secretref.Binding{}, product.ErrStoreUnavailable
	}
	binding, err := s.bindings.BindingForOpen(tenantID, handle.BindingDigest, handle.ProviderKeyID, handle.KMSKeyVersion)
	if err != nil || handle.envelope().Validate(binding) != nil {
		return keyHandle{}, secretref.Binding{}, providerError(err)
	}
	return handle, binding, nil
}

func (s *Store) validateHandleForCleanup(tenantID, keyReference string) error {
	handle, err := decodeKeyHandle(keyReference)
	if err != nil {
		return product.ErrStoreUnavailable
	}
	binding, err := s.bindings.BindingForHandle(tenantID, handle.BindingDigest, handle.ProviderKeyID, handle.KMSKeyVersion)
	if err != nil || handle.envelope().Validate(binding) != nil {
		return product.ErrStoreUnavailable
	}
	return nil
}

func (s *Store) segmentPath(tenantID, recordingID, reference string) (string, bool) {
	sequence, ok := parseSegmentReference(recordingID, reference)
	if !ok || !validID(tenantID) || sequence < 1 || sequence > product.MaxRecordingSegments {
		return "", false
	}
	sum := sha256.Sum256([]byte(reference))
	return filepath.Join(s.recordingDirectory(tenantID, recordingID), hex.EncodeToString(sum[:])+".segment"), true
}

func (s *Store) recordingDirectory(tenantID, recordingID string) string {
	identity, _ := canonicalJSON(recordingDirectoryIdentity{Schema: directoryIdentitySchema, TenantID: tenantID, RecordingID: recordingID})
	sum := sha256.Sum256(identity)
	return filepath.Join(s.directory, hex.EncodeToString(sum[:]))
}

func parseSegmentReference(recordingID, reference string) (int64, bool) {
	parts := strings.Split(reference, ":")
	if !validID(recordingID) || len(parts) != 3 || parts[0] != "recording" || parts[1] != recordingID || strings.ContainsAny(reference, "/\\\x00") {
		return 0, false
	}
	sequence, err := strconv.ParseInt(parts[2], 10, 64)
	return sequence, err == nil && strconv.FormatInt(sequence, 10) == parts[2]
}

func validSegmentFilename(name string) bool {
	if len(name) != 64+len(".segment") || !strings.HasSuffix(name, ".segment") {
		return false
	}
	digest := strings.TrimSuffix(name, ".segment")
	decoded, err := hex.DecodeString(digest)
	return err == nil && len(decoded) == sha256.Size && digest == strings.ToLower(digest)
}

func ensurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return product.ErrStoreUnavailable
		}
		info, err = os.Lstat(path)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return product.ErrStoreUnavailable
	}
	return nil
}

func privateDirectoryState(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return false, product.ErrStoreUnavailable
	}
	return true, nil
}

func ensureStoreRoot(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return product.ErrStoreUnavailable
		}
		info, err = os.Lstat(path)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return product.ErrInvalid
	}
	return nil
}

func readPrivateFile(ctx context.Context, path string, maximum int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, product.ErrStoreUnavailable
	}
	file := os.NewFile(uintptr(fd), "kms-recording-segment")
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > maximum {
		return nil, product.ErrStoreUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	document, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(document) < 1 || int64(len(document)) != info.Size() || int64(len(document)) > maximum {
		clear(document)
		return nil, product.ErrStoreUnavailable
	}
	return document, nil
}

func writeFull(ctx context.Context, file *os.File, document []byte) error {
	for written := 0; written < len(document); {
		if err := ctx.Err(); err != nil {
			return err
		}
		count, err := file.Write(document[written:])
		written += count
		if err != nil || count == 0 {
			return product.ErrStoreUnavailable
		}
	}
	return nil
}

func providerError(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return product.ErrStoreUnavailable
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
