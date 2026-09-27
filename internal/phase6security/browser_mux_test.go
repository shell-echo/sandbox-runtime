package phase6security

import "testing"

func TestBrowserAllocationMuxRequiresExactUnixOwnerAndPeer(t *testing.T) {
	for name, mutate := range map[string]func(*Profile){
		"missing peer edge": func(profile *Profile) {
			for index, edge := range profile.TrustEdges {
				if edge.ID == BrowserMuxUnixEdgeID {
					profile.TrustEdges = append(profile.TrustEdges[:index], profile.TrustEdges[index+1:]...)
					return
				}
			}
		},
		"wrong peer": func(profile *Profile) {
			for index := range profile.TrustEdges {
				if profile.TrustEdges[index].ID == BrowserMuxUnixEdgeID {
					profile.TrustEdges[index].From = "gateway-runtime"
				}
			}
		},
		"backend owns socket": func(profile *Profile) {
			for index := range profile.Principals {
				if profile.Principals[index].Name != "browser-executor-backend" {
					continue
				}
				for mountIndex := range profile.Principals[index].Mounts {
					if profile.Principals[index].Mounts[mountIndex].StorageID == BrowserMuxSocketStorageID {
						profile.Principals[index].Mounts[mountIndex].ReadOnly = false
					}
				}
			}
		},
		"extra socket consumer": func(profile *Profile) {
			for index := range profile.Principals {
				if profile.Principals[index].Name == "gateway-runtime" {
					profile.Principals[index].Mounts = append(profile.Principals[index].Mounts,
						Mount{Target: BrowserMuxSocketDirectory, Kind: "private_socket", ReadOnly: true, StorageID: BrowserMuxSocketStorageID})
				}
			}
		},
		"missing unix listener": func(profile *Profile) {
			for index := range profile.Principals {
				if profile.Principals[index].Name == "provider-browser-runtime" {
					for listenerIndex, listener := range profile.Principals[index].Listeners {
						if listener.Name == "browser-mux" {
							profile.Principals[index].Listeners = append(profile.Principals[index].Listeners[:listenerIndex], profile.Principals[index].Listeners[listenerIndex+1:]...)
							return
						}
					}
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			profile := validProfile()
			mutate(&profile)
			profile.ProfileDigest = profile.Digest()
			if profile.Validate() == nil {
				t.Fatal("Browser allocation mux drift was accepted")
			}
		})
	}
}
