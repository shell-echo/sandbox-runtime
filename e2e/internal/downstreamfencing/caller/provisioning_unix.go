//go:build darwin || linux

package caller

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

const (
	bootstrapRequestFD = 3
	endpointResultFD   = 4
	finalConfigFD      = 5
)

type InheritedProvisioning struct {
	request *os.File
	result  *os.File
	final   *os.File
}

// OpenInheritedProvisioning validates all fixed descriptors before taking
// ownership. On failure it leaves every descriptor untouched because a
// runtime or launcher descriptor must never be closed by partial validation.
func OpenInheritedProvisioning() (*InheritedProvisioning, error) {
	for _, expected := range []struct {
		fd     int
		access int
	}{
		{fd: bootstrapRequestFD, access: unix.O_RDONLY},
		{fd: endpointResultFD, access: unix.O_WRONLY},
		{fd: finalConfigFD, access: unix.O_RDONLY},
	} {
		if validateProvisioningFD(expected.fd, expected.access) != nil {
			return nil, errors.New("invalid inherited provisioning files")
		}
	}
	for _, fd := range []int{bootstrapRequestFD, endpointResultFD, finalConfigFD} {
		unix.CloseOnExec(fd)
	}
	return &InheritedProvisioning{
		request: os.NewFile(bootstrapRequestFD, "downstream-bootstrap-request"),
		result:  os.NewFile(endpointResultFD, "downstream-endpoint-result"),
		final:   os.NewFile(finalConfigFD, "downstream-final-config"),
	}, nil
}

func validateProvisioningFile(file *os.File, accessMode int) error {
	if file == nil {
		return errors.New("invalid provisioning file")
	}
	if err := validateProvisioningFD(int(file.Fd()), accessMode); err != nil {
		return err
	}
	unix.CloseOnExec(int(file.Fd()))
	return nil
}

func validateProvisioningFD(fd, accessMode int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFIFO {
		return errors.New("provisioning file is not a FIFO")
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != accessMode {
		return errors.New("provisioning file direction is invalid")
	}
	return nil
}

func (f *InheritedProvisioning) Close() error {
	if f == nil {
		return nil
	}
	var errs []error
	for _, file := range []*os.File{f.request, f.result, f.final} {
		if file != nil {
			errs = append(errs, file.Close())
		}
	}
	f.request, f.result, f.final = nil, nil, nil
	return errors.Join(errs...)
}
