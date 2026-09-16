//go:build !darwin && !linux

package qualificationharness

import "context"

func validPersistentStateRoot(string) bool { return false }

func createPersistentState(context.Context, string) (*persistentState, error) {
	return nil, errPersistentState
}

func recheckPersistentState(context.Context, *persistentState) error {
	return errPersistentState
}
