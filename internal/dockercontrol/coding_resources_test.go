package dockercontrol

import (
	"errors"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestCodingResourceSetBindsOneEffectAndExactFiveObjects(t *testing.T) {
	a, plan, now := testReceiptAuthority(t)
	binding := testReceiptBinding(a, plan)
	set, err := NewCodingResourceSet(binding, a)
	if err != nil {
		t.Fatal(err)
	}
	prep, err := set.ContainerName(CodingPreparationRole)
	if err != nil || prep != "sandbox-runtime-coding-prep-"+strings.TrimPrefix(a.EffectID, "sha256:") {
		t.Fatalf("preparation name = %q, %v", prep, err)
	}
	runtime, err := set.ContainerName(CodingRuntimeRole)
	if err != nil || runtime != "sandbox-runtime-coding-runtime-"+strings.TrimPrefix(a.EffectID, "sha256:") || prep == runtime {
		t.Fatalf("runtime name = %q, %v", runtime, err)
	}
	mounts := set.Mounts()
	if len(mounts) != 3 || mounts[0].Target != "/inputs" || !mounts[0].ReadOnly ||
		mounts[1].Target != "/workspace" || mounts[1].ReadOnly ||
		mounts[2].Target != "/outputs" || mounts[2].ReadOnly {
		t.Fatalf("closed mounts = %#v", mounts)
	}
	mounts[0].Name = "tampered"
	if set.Mounts()[0].Name == "tampered" {
		t.Fatal("mutable mount projection escaped")
	}
	for _, role := range []CodingResourceRole{CodingPreparationRole, CodingRuntimeRole,
		CodingInputsRole, CodingWorkspaceRole, CodingOutputsRole} {
		labels, err := set.Labels(role)
		if err != nil || len(labels) != 8 || labels[codingEffectLabel] != a.EffectID ||
			labels[codingAuthorityLabel] != a.Digest() || labels[codingProfileLabel] != a.ProfileDigest ||
			labels[codingPlanLabel] != a.PlanDigest || labels[codingSlotLabel] != a.SlotID ||
			labels[codingTemplateLabel] != plan.TemplateDigest ||
			labels[codingRoleLabel] != string(role) || labels[codingManagedLabel] != "true" {
			t.Fatalf("%s labels = %#v, %v", role, labels, err)
		}
		volume := role == CodingInputsRole || role == CodingWorkspaceRole || role == CodingOutputsRole
		if err := set.MatchLabels(role, labels); volume && err != nil || !volume && !errors.Is(err, ErrInvalidAuthority) {
			t.Fatalf("%s volume-label scope = %v", role, err)
		}
		labels[codingEffectLabel] = "tampered"
		if err := set.MatchLabels(role, labels); !errors.Is(err, ErrInvalidAuthority) {
			t.Fatalf("%s foreign-effect labels admitted: %v", role, err)
		}
		fresh, _ := set.Labels(role)
		if fresh[codingEffectLabel] != a.EffectID {
			t.Fatal("mutable label projection escaped")
		}
		fresh["unexpected"] = "value"
		if err := set.MatchLabels(role, fresh); !errors.Is(err, ErrInvalidAuthority) {
			t.Fatalf("%s extra labels admitted: %v", role, err)
		}
	}
	for index, role := range []CodingResourceRole{CodingInputsRole, CodingWorkspaceRole, CodingOutputsRole} {
		name, err := set.VolumeName(role)
		if err != nil || name != set.Mounts()[index].Name {
			t.Fatalf("%s volume name = %q, %v", role, name, err)
		}
	}
	if _, err := set.VolumeName(CodingRuntimeRole); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatalf("container interpreted as volume = %v", err)
	}
	if _, err := set.Labels("root"); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatalf("extra role labels = %v", err)
	}
	if _, err := set.ContainerName(CodingInputsRole); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatalf("volume interpreted as container = %v", err)
	}
	if _, err := (CodingResourceSet{}).ContainerName(CodingRuntimeRole); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatalf("zero resource set = %v", err)
	}
	other := otherReceiptAuthority(t, "b", 1, now)
	otherSet, err := NewCodingResourceSet(binding, other)
	if err != nil || otherSet.Mounts()[0].Name == set.Mounts()[0].Name {
		t.Fatalf("different allocation reused volume set: %v", err)
	}
	otherRuntime, _ := otherSet.ContainerName(CodingRuntimeRole)
	if otherRuntime == runtime {
		t.Fatal("different effect reused runtime name")
	}
}

func TestCodingContainerLabelsMergeVerifiedImageInheritance(t *testing.T) {
	a, plan, _ := testReceiptAuthority(t)
	set, err := NewCodingResourceSet(testReceiptBinding(a, plan), a)
	if err != nil {
		t.Fatal(err)
	}
	binding, _ := set.Labels(CodingRuntimeRole)
	image := map[string]string{
		"org.opencontainers.image.title":                            "sandbox-runtime coding/shell guest",
		"org.opencontainers.image.source":                           "https://github.com/shell-echo/sandbox-runtime",
		"io.github.shell-echo.sandbox-runtime.profile":              "sandbox-runtime-coding-shell-v1",
		"io.github.shell-echo.sandbox-runtime.terminal-broker-path": "/usr/local/libexec/sandbox-runtime/terminal-broker",
	}
	merged, err := mergeCodingContainerLabels(image, binding)
	if err != nil || len(merged) != len(image)+len(binding) ||
		merged["org.opencontainers.image.title"] != image["org.opencontainers.image.title"] ||
		merged[codingEffectLabel] != a.EffectID {
		t.Fatalf("image inheritance merge = %#v, %v", merged, err)
	}
	merged["org.opencontainers.image.title"] = "drift"
	if err := matchEffectiveCodingContainerLabels(merged, merged); err != nil {
		t.Fatal(err)
	}
	observed := map[string]string{}
	for key, value := range merged {
		observed[key] = value
	}
	observed["unexpected"] = "value"
	if err := matchEffectiveCodingContainerLabels(merged, observed); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatalf("extra effective container label admitted: %v", err)
	}
	delete(observed, "unexpected")
	delete(observed, "org.opencontainers.image.source")
	if err := matchEffectiveCodingContainerLabels(merged, observed); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatalf("missing inherited image label admitted: %v", err)
	}
	if image["org.opencontainers.image.title"] == "drift" {
		t.Fatal("merged label mutation escaped into image source")
	}
	image[codingEffectLabel] = a.EffectID
	if _, err := mergeCodingContainerLabels(image, binding); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatalf("image/binding key collision admitted: %v", err)
	}
	delete(image, codingEffectLabel)
	wrongBinding := map[string]string{}
	for key, value := range binding {
		wrongBinding[key] = value
	}
	delete(wrongBinding, codingPlanLabel)
	if _, err := mergeCodingContainerLabels(image, wrongBinding); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatalf("missing binding label admitted: %v", err)
	}
	if _, err := set.ContainerLabels(CodingInputsRole, phase6security.CodingRuntimeTemplateV2{},
		phase6security.ImageDescriptorDocuments{}); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatalf("volume interpreted as container: %v", err)
	}
}

func TestCodingResourceSetRejectsAuthorityOrPlanDrift(t *testing.T) {
	a, plan, _ := testReceiptAuthority(t)
	binding := testReceiptBinding(a, plan)
	for name, alter := range map[string]func(*CodingCreateAuthority){
		"slot":    func(value *CodingCreateAuthority) { value.SlotID = "other" },
		"effect":  func(value *CodingCreateAuthority) { value.EffectID = testControlDigest("0") },
		"fence":   func(value *CodingCreateAuthority) { value.Fence++ },
		"profile": func(value *CodingCreateAuthority) { value.ProfileDigest = testControlDigest("0") },
	} {
		t.Run(name, func(t *testing.T) {
			changed := a
			alter(&changed)
			if _, err := NewCodingResourceSet(binding, changed); !errors.Is(err, ErrInvalidAuthority) {
				t.Fatalf("drift admitted: %v", err)
			}
		})
	}
	wrong := binding.clone()
	wrong.SpecBySlot[a.SlotID] = testControlDigest("0")
	if _, err := NewCodingResourceSet(wrong, a); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatalf("spec-map drift admitted: %v", err)
	}
}
