//go:build !darwin && !linux

package evidencefiles

import "errors"

const unsupportedPlatformMessage = "secure evidence-root descriptors require Darwin or Linux"

func unsupportedPlatformError() error {
	return errors.New(unsupportedPlatformMessage)
}

// Root is unavailable on platforms without the required openat semantics.
type Root struct{}

// Publication is unavailable on platforms without the required openat
// semantics.
type Publication struct{}

func OpenRoot(string) (*Root, error) {
	return nil, unsupportedPlatformError()
}

func (*Root) Close() error { return nil }

func (*Root) Read([]string, Options) (Inventory, error) {
	return Inventory{}, unsupportedPlatformError()
}

func (*Root) ReadFile(string, int64) ([]byte, error) {
	return nil, unsupportedPlatformError()
}

func (*Root) Publish(string, []byte, int64) (*Publication, error) {
	return nil, unsupportedPlatformError()
}

func (*Publication) Path() string { return "" }

func (*Publication) Size() int64 { return 0 }

func (*Publication) Read(int64) ([]byte, error) {
	return nil, unsupportedPlatformError()
}

func (*Publication) Commit(string) error {
	return unsupportedPlatformError()
}

func (*Publication) Remove() error {
	return unsupportedPlatformError()
}
