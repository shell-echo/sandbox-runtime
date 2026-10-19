package controlstorage

type sourceSession struct{ identity sourceIdentity }

func openSource(Binding, DedicatedBackend, string, string) (*sourceSession, error) {
	return nil, ErrInvalid
}
func (s *sourceSession) check(uint64) error { return ErrInvalid }
func (s *sourceSession) close() error       { return nil }
