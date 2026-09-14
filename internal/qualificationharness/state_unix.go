//go:build darwin || linux

package qualificationharness

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func createPersistentState(ctx context.Context, rootPath string) (_ *persistentState, resultErr error) {
	if ctx == nil || !validPersistentStateRoot(rootPath) {
		return nil, errPersistentState
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	parent, err := openStateDirectory(ctx, filepath.Dir(rootPath))
	if err != nil || !admissibleStateDirectory(parent.info, false) {
		if parent != nil && parent.file != nil {
			_ = parent.file.Close()
		}
		return nil, persistentStateContextError(ctx)
	}
	state := &persistentState{parent: parent, stores: make(map[string]*stateDirectoryPin, 3)}
	created := false
	defer func() {
		if resultErr != nil {
			_ = state.close()
			if created {
				resultErr = errors.Join(resultErr, ErrPersistentStateRetained)
			}
		}
	}()
	rootName := filepath.Base(rootPath)
	if unix.Mkdirat(int(parent.file.Fd()), rootName, 0700) != nil {
		return nil, errPersistentState
	}
	created = true
	state.root, err = openStateDirectoryAt(parent, rootName, rootPath)
	if err != nil || !admissibleStateDirectory(state.root.info, true) {
		return nil, persistentStateContextError(ctx)
	}
	for _, storeID := range persistentStoreIDs() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		leaf := persistentStateLeaf(storeID)
		if unix.Mkdirat(int(state.root.file.Fd()), leaf, 0700) != nil {
			return nil, errPersistentState
		}
		storePath := filepath.Join(rootPath, leaf)
		store, err := openStateDirectoryAt(state.root, leaf, storePath)
		if err != nil || !admissibleStateDirectory(store.info, true) {
			return nil, persistentStateContextError(ctx)
		}
		state.stores[storeID] = store
	}
	if err := recheckPersistentState(ctx, state); err != nil {
		return nil, err
	}
	return state, nil
}

func persistentStateLeaf(storeID string) string {
	switch storeID {
	case ProviderLocalState:
		return ProviderLocalState
	case CallerOwnedCorrelationState:
		return CallerOwnedCorrelationState
	case RuntimeResourceState:
		return RuntimeResourceState
	default:
		return ""
	}
}

func validPersistentStateRoot(value string) bool {
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value || value == string(filepath.Separator) {
		return false
	}
	leaf := filepath.Base(value)
	if leaf == "." || leaf == ".." || len(leaf) == 0 || len(leaf) > 128 || !asciiAlphaNumeric(leaf[0]) {
		return false
	}
	for index := 1; index < len(leaf); index++ {
		if !asciiAlphaNumeric(leaf[index]) && leaf[index] != '.' && leaf[index] != '_' && leaf[index] != '-' {
			return false
		}
	}
	return true
}

func asciiAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func openStateDirectory(ctx context.Context, value string) (*stateDirectoryPin, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errPersistentState
	}
	file := os.NewFile(uintptr(fd), "qualification-state-directory")
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, errPersistentState
	}
	pin := &stateDirectoryPin{file: file, info: info, path: string(filepath.Separator), ancestors: []os.FileInfo{info}}
	if value == string(filepath.Separator) {
		return pin, nil
	}
	for _, component := range strings.Split(strings.TrimPrefix(value, string(filepath.Separator)), string(filepath.Separator)) {
		if err := ctx.Err(); err != nil {
			_ = pin.file.Close()
			return nil, err
		}
		nextFD, err := unix.Openat(int(pin.file.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err != nil {
			_ = pin.file.Close()
			return nil, errPersistentState
		}
		next := os.NewFile(uintptr(nextFD), "qualification-state-directory")
		info, statErr := next.Stat()
		closeErr := pin.file.Close()
		if statErr != nil || closeErr != nil {
			_ = next.Close()
			return nil, errPersistentState
		}
		pin.file, pin.info = next, info
		pin.ancestors = append(pin.ancestors, info)
	}
	pin.path = value
	return pin, nil
}

func openStateDirectoryAt(parent *stateDirectoryPin, name, value string) (*stateDirectoryPin, error) {
	fd, err := unix.Openat(int(parent.file.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errPersistentState
	}
	file := os.NewFile(uintptr(fd), "qualification-state-directory")
	info, err := file.Stat()
	if err != nil || !stateDirectoryMatchesParent(parent.file, name, info) {
		_ = file.Close()
		return nil, errPersistentState
	}
	return &stateDirectoryPin{file: file, info: info, path: value, name: name}, nil
}

func admissibleStateDirectory(info os.FileInfo, private bool) bool {
	if info == nil || !info.IsDir() || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	if private {
		return info.Mode().Perm() == 0700 && stat.Uid == uint32(os.Geteuid())
	}
	return info.Mode().Perm()&0022 == 0 && (stat.Uid == uint32(os.Geteuid()) || stat.Uid == 0)
}

func stateDirectoryMatchesParent(parent *os.File, name string, info os.FileInfo) bool {
	if parent == nil || info == nil {
		return false
	}
	var current unix.Stat_t
	if unix.Fstatat(int(parent.Fd()), name, &current, unix.AT_SYMLINK_NOFOLLOW) != nil || current.Mode&unix.S_IFMT != unix.S_IFDIR {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Dev) == uint64(current.Dev) && stat.Ino == current.Ino
}

func sameStateDirectory(first, second os.FileInfo) bool {
	if first == nil || second == nil || !first.IsDir() || !second.IsDir() || !os.SameFile(first, second) || first.Mode() != second.Mode() {
		return false
	}
	a, aok := first.Sys().(*syscall.Stat_t)
	b, bok := second.Sys().(*syscall.Stat_t)
	return aok && bok && a.Uid == b.Uid && a.Gid == b.Gid
}

func recheckPersistentState(ctx context.Context, state *persistentState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if state == nil || state.parent == nil || state.root == nil || len(state.stores) != 3 ||
		!admissibleStateDirectory(state.parent.info, false) || !admissibleStateDirectory(state.root.info, true) {
		return errPersistentState
	}
	currentParent, err := openStateDirectory(ctx, state.parent.path)
	if err != nil {
		return persistentStateContextError(ctx)
	}
	defer currentParent.file.Close()
	if !sameStateDirectory(state.parent.info, currentParent.info) || len(state.parent.ancestors) != len(currentParent.ancestors) {
		return errPersistentState
	}
	for index := range state.parent.ancestors {
		if !sameStateDirectory(state.parent.ancestors[index], currentParent.ancestors[index]) {
			return errPersistentState
		}
	}
	rootInfo, err := state.root.file.Stat()
	if err != nil || !sameStateDirectory(state.root.info, rootInfo) || !admissibleStateDirectory(rootInfo, true) ||
		!stateDirectoryMatchesParent(state.parent.file, state.root.name, rootInfo) {
		return errPersistentState
	}
	for _, storeID := range persistentStoreIDs() {
		if err := ctx.Err(); err != nil {
			return err
		}
		store := state.stores[storeID]
		if store == nil || store.file == nil {
			return errPersistentState
		}
		info, err := store.file.Stat()
		if err != nil || !sameStateDirectory(store.info, info) || !admissibleStateDirectory(info, true) ||
			!stateDirectoryMatchesParent(state.root.file, store.name, info) {
			return errPersistentState
		}
	}
	return nil
}

func persistentStateContextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(errPersistentState, err)
	}
	return errPersistentState
}
