package phase6security

// VerifySlice6GuestReceiptLocalProfile admits only the already validated
// Product/Guest local-image candidate boundary for private evidence emission.
// This is runtime configuration admission, not OCI provenance: the external
// gate must independently verify both actual image artifacts and containers.
func VerifySlice6GuestReceiptLocalProfile(profile Profile, origin string) error {
	_, guest, product, _, _, err := profile.GuestProductBoundary(origin)
	if err != nil || !localGuestReceiptImage(guest) || !localGuestReceiptImage(product) {
		return ErrInvalidProfile
	}
	return nil
}

func localGuestReceiptImage(principal Principal) bool {
	return principal.ImageLocation == "local" && principal.ImageReference == principal.ImageDigest &&
		(principal.ImageIdentityKind == ImageIdentityOCIManifest || principal.ImageIdentityKind == ImageIdentityOCIIndex) &&
		validImageIdentity(principal.ImageLocation, principal.ImageIdentityKind, principal.ImageReference,
			principal.ImageDigest, principal.ImagePlatform, principal.ImageSelectedManifestDigest, principal.ImageConfigDigest)
}
