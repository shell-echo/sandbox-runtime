package phase6profilebuilder

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

type slice6SeccompCondition struct {
	Caps      []string `json:"caps"`
	Arches    []string `json:"arches"`
	MinKernel string   `json:"minKernel"`
	MaxKernel string   `json:"maxKernel"`
}

type slice6SeccompArg struct {
	Index    uint   `json:"index"`
	Value    uint64 `json:"value"`
	ValueTwo uint64 `json:"valueTwo"`
	Op       string `json:"op"`
}

type slice6SeccompDocument struct {
	DefaultAction   string `json:"defaultAction"`
	DefaultErrnoRet *uint  `json:"defaultErrnoRet"`
	ArchMap         []struct {
		Architecture     string   `json:"architecture"`
		SubArchitectures []string `json:"subArchitectures"`
	} `json:"archMap"`
	Syscalls []struct {
		Names    []string               `json:"names"`
		Action   string                 `json:"action"`
		ErrnoRet *uint                  `json:"errnoRet"`
		Args     []slice6SeccompArg     `json:"args"`
		Comment  string                 `json:"comment"`
		Includes slice6SeccompCondition `json:"includes"`
		Excludes slice6SeccompCondition `json:"excludes"`
	} `json:"syscalls"`
}

// validateSlice6SeccompJSON checks only the closed policy shape, default
// denial and selected architecture. It does not establish that a syscall set
// is least privilege; that requires original-byte review and real probes.
func validateSlice6SeccompJSON(document []byte, platform string) error {
	if len(document) == 0 || len(document) > 1<<20 || rejectSlice6DuplicateJSONKeys(document) != nil {
		return ErrInvalidResourceSeccompSupply
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var policy slice6SeccompDocument
	if decoder.Decode(&policy) != nil || decoder.Decode(new(any)) != io.EOF ||
		policy.DefaultAction != "SCMP_ACT_ERRNO" || len(policy.ArchMap) == 0 ||
		len(policy.ArchMap) > 16 || len(policy.Syscalls) == 0 || len(policy.Syscalls) > 1024 {
		return ErrInvalidResourceSeccompSupply
	}
	if policy.DefaultErrnoRet != nil && (*policy.DefaultErrnoRet < 1 || *policy.DefaultErrnoRet > 4095) {
		return ErrInvalidResourceSeccompSupply
	}
	wantedArch := "SCMP_ARCH_X86_64"
	if platform == "linux/arm64/v8" {
		wantedArch = "SCMP_ARCH_AARCH64"
	} else if platform != "linux/amd64" {
		return ErrInvalidResourceSeccompSupply
	}
	seenArch := make(map[string]bool, len(policy.ArchMap))
	for _, mapping := range policy.ArchMap {
		if !strings.HasPrefix(mapping.Architecture, "SCMP_ARCH_") || seenArch[mapping.Architecture] {
			return ErrInvalidResourceSeccompSupply
		}
		seenArch[mapping.Architecture] = true
	}
	if !seenArch[wantedArch] {
		return ErrInvalidResourceSeccompSupply
	}
	for _, rule := range policy.Syscalls {
		if len(rule.Names) == 0 || len(rule.Names) > 512 ||
			(rule.Action != "SCMP_ACT_ALLOW" && rule.Action != "SCMP_ACT_ERRNO" &&
				rule.Action != "SCMP_ACT_KILL_PROCESS") || len(rule.Args) > 6 ||
			(rule.ErrnoRet != nil && (rule.Action != "SCMP_ACT_ERRNO" || *rule.ErrnoRet < 1 || *rule.ErrnoRet > 4095)) {
			return ErrInvalidResourceSeccompSupply
		}
		seenNames := make(map[string]bool, len(rule.Names))
		for _, name := range rule.Names {
			if !validSlice6SyscallName(name) || seenNames[name] {
				return ErrInvalidResourceSeccompSupply
			}
			seenNames[name] = true
		}
		for _, argument := range rule.Args {
			if argument.Index > 5 || !validSlice6SeccompOperator(argument.Op) {
				return ErrInvalidResourceSeccompSupply
			}
		}
	}
	return nil
}

func validSlice6SeccompOperator(value string) bool {
	switch value {
	case "SCMP_CMP_NE", "SCMP_CMP_LT", "SCMP_CMP_LE", "SCMP_CMP_EQ", "SCMP_CMP_GE", "SCMP_CMP_GT", "SCMP_CMP_MASKED_EQ":
		return true
	default:
		return false
	}
}

func validSlice6SyscallName(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func rejectSlice6DuplicateJSONKeys(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	if readSlice6JSONValue(decoder, 0) != nil {
		return ErrInvalidResourceSeccompSupply
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrInvalidResourceSeccompSupply
	}
	return nil
}

func readSlice6JSONValue(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return ErrInvalidResourceSeccompSupply
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalidResourceSeccompSupply
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, okay := keyToken.(string)
			if err != nil || !okay || seen[key] {
				return ErrInvalidResourceSeccompSupply
			}
			seen[key] = true
			if readSlice6JSONValue(decoder, depth+1) != nil {
				return ErrInvalidResourceSeccompSupply
			}
		}
	case '[':
		for decoder.More() {
			if readSlice6JSONValue(decoder, depth+1) != nil {
				return ErrInvalidResourceSeccompSupply
			}
		}
	default:
		return ErrInvalidResourceSeccompSupply
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim(delimiter+2) { // '{'→'}', '['→']'
		return ErrInvalidResourceSeccompSupply
	}
	return nil
}
