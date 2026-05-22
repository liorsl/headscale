package mapper

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
)

var iap = func(ipStr string) *netip.Addr {
	ip := netip.MustParseAddr(ipStr)
	return &ip
}

func TestDNSConfigMapResponse(t *testing.T) {
	tests := []struct {
		magicDNS bool
		want     *tailcfg.DNSConfig
	}{
		{
			magicDNS: true,
			want: &tailcfg.DNSConfig{
				Routes: map[string][]*dnstype.Resolver{},
				Domains: []string{
					"foobar.headscale.net",
				},
				Proxied: true,
			},
		},
		{
			magicDNS: false,
			want: &tailcfg.DNSConfig{
				Domains: []string{"foobar.headscale.net"},
				Proxied: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("with-magicdns-%v", tt.magicDNS), func(t *testing.T) {
			mach := func(hostname, username string, userid uint) *types.Node {
				return &types.Node{
					Hostname: hostname,
					UserID:   new(userid),
					User: &types.User{
						Name: username,
					},
				}
			}

			baseDomain := "foobar.headscale.net"

			dnsConfigOrig := tailcfg.DNSConfig{
				Routes:  make(map[string][]*dnstype.Resolver),
				Domains: []string{baseDomain},
				Proxied: tt.magicDNS,
			}

			nodeInShared1 := mach("test_get_shared_nodes_1", "shared1", 1)

			got := generateDNSConfig(
				&types.Config{
					TailcfgDNSConfig: &dnsConfigOrig,
				},
				nodeInShared1.View(),
				nil,
			)

			if diff := cmp.Diff(tt.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("expandAlias() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGenerateDNSConfigProfiles(t *testing.T) {
	defaultResolvers := []*dnstype.Resolver{{Addr: "1.1.1.1"}}

	baseDNS := &tailcfg.DNSConfig{
		Routes:    make(map[string][]*dnstype.Resolver),
		Domains:   []string{"example.com"},
		Proxied:   true,
		Resolvers: defaultResolvers,
	}

	profiles := map[string]types.DNSProfile{
		"corp": {Nameservers: []string{"10.0.0.1", "10.0.0.2"}},
		"home": {Nameservers: []string{"8.8.8.8", "8.8.4.4"}},
	}

	mkCapMap := func(caps ...string) tailcfg.NodeCapMap {
		out := tailcfg.NodeCapMap{}
		for _, c := range caps {
			out[tailcfg.NodeCapability(c)] = []tailcfg.RawMessage{}
		}
		return out
	}

	tests := []struct {
		name   string
		capMap tailcfg.NodeCapMap
		want   []*dnstype.Resolver
	}{
		{
			name:   "matching-profile-replaces-resolvers",
			capMap: mkCapMap("dnsprofile:corp"),
			want:   []*dnstype.Resolver{{Addr: "10.0.0.1"}, {Addr: "10.0.0.2"}},
		},
		{
			name:   "unknown-profile-keeps-default",
			capMap: mkCapMap("dnsprofile:nope"),
			want:   defaultResolvers,
		},
		{
			name:   "no-dnsprofile-cap-keeps-default",
			capMap: nil,
			want:   defaultResolvers,
		},
		{
			// Multi-cap pick is deterministic: candidates are sorted
			// and the first wins. "corp" sorts before "home".
			name:   "multiple-profiles-sorted-pick",
			capMap: mkCapMap("dnsprofile:home", "dnsprofile:corp"),
			want:   []*dnstype.Resolver{{Addr: "10.0.0.1"}, {Addr: "10.0.0.2"}},
		},
		{
			name:   "malformed-profile-name-rejected",
			capMap: mkCapMap("dnsprofile:bad/name"),
			want:   defaultResolvers,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateDNSConfig(
				&types.Config{
					TailcfgDNSConfig: baseDNS,
					DNSConfig: types.DNSConfig{
						Profiles: profiles,
					},
				},
				(&types.Node{ID: 1, Hostname: "n1"}).View(),
				tt.capMap,
			)

			if diff := cmp.Diff(tt.want, got.Resolvers, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("generateDNSConfig() resolvers mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDNSProfileComposesWithNextDNS verifies that a `dnsprofile:` cap
// rewrites Resolvers first, and a `nextdns:` cap then rewrites any
// NextDNS DoH host in the new resolver list. The two attribute families
// are independent and must compose without one clobbering the other.
func TestDNSProfileComposesWithNextDNS(t *testing.T) {
	t.Parallel()

	cfg := &types.Config{
		TailcfgDNSConfig: &tailcfg.DNSConfig{
			Resolvers: []*dnstype.Resolver{{Addr: "https://dns.nextdns.io/global"}},
		},
		DNSConfig: types.DNSConfig{
			Profiles: map[string]types.DNSProfile{
				"viaprofile": {Nameservers: []string{"https://dns.nextdns.io/fromprofile"}},
			},
		},
	}

	node := (&types.Node{
		ID:       1,
		Hostname: "n1",
		IPv4:     iap("100.64.0.1"),
		Hostinfo: &tailcfg.Hostinfo{OS: "linux"},
	}).View()

	got := generateDNSConfig(cfg, node, tailcfg.NodeCapMap{
		"dnsprofile:viaprofile": []tailcfg.RawMessage{},
		"nextdns:override":      []tailcfg.RawMessage{},
	})

	want := "https://dns.nextdns.io/override?device_ip=100.64.0.1&device_model=linux&device_name=n1"
	if len(got.Resolvers) != 1 || got.Resolvers[0].Addr != want {
		t.Errorf("resolvers = %#v, want single addr %q", got.Resolvers, want)
	}
}

func TestNextDNSCapMapRendering(t *testing.T) {
	t.Parallel()

	mkConfig := func(addrs ...string) *types.Config {
		resolvers := make([]*dnstype.Resolver, len(addrs))
		for i, a := range addrs {
			resolvers[i] = &dnstype.Resolver{Addr: a}
		}

		return &types.Config{
			TailcfgDNSConfig: &tailcfg.DNSConfig{
				Resolvers: resolvers,
			},
		}
	}

	mkNode := func() types.NodeView {
		return (&types.Node{
			ID:       1,
			Hostname: "node1",
			IPv4:     iap("100.64.0.1"),
			Hostinfo: &tailcfg.Hostinfo{OS: "linux"},
		}).View()
	}

	// resolverAddr extracts the first resolver's address with a
	// bounds check. Without it, a regression that drops the
	// resolver list would nil-panic instead of failing cleanly.
	resolverAddr := func(t *testing.T, got *tailcfg.DNSConfig) string {
		t.Helper()

		if got == nil {
			t.Fatalf("generateDNSConfig returned nil")
		}

		if len(got.Resolvers) == 0 {
			t.Fatalf("generateDNSConfig returned no Resolvers")
		}

		return got.Resolvers[0].Addr
	}

	t.Run("no_capmap_metadata_appended", func(t *testing.T) {
		t.Parallel()

		got := generateDNSConfig(
			mkConfig("https://dns.nextdns.io/abc"),
			mkNode(),
			nil,
		)

		want := "https://dns.nextdns.io/abc?device_ip=100.64.0.1&device_model=linux&device_name=node1"
		if addr := resolverAddr(t, got); addr != want {
			t.Errorf("addr = %q, want %q", addr, want)
		}
	})

	t.Run("profile_overrides_global", func(t *testing.T) {
		t.Parallel()

		capMap := tailcfg.NodeCapMap{
			"nextdns:override": []tailcfg.RawMessage{},
		}

		got := generateDNSConfig(
			mkConfig("https://dns.nextdns.io/global"),
			mkNode(),
			capMap,
		)

		want := "https://dns.nextdns.io/override?device_ip=100.64.0.1&device_model=linux&device_name=node1"
		if addr := resolverAddr(t, got); addr != want {
			t.Errorf("addr = %q, want %q", addr, want)
		}
	})

	t.Run("no_device_info_skips_metadata", func(t *testing.T) {
		t.Parallel()

		capMap := tailcfg.NodeCapMap{
			"nextdns:abc":            []tailcfg.RawMessage{},
			"nextdns:no-device-info": []tailcfg.RawMessage{},
		}

		got := generateDNSConfig(
			mkConfig("https://dns.nextdns.io/global"),
			mkNode(),
			capMap,
		)

		want := "https://dns.nextdns.io/abc"
		if addr := resolverAddr(t, got); addr != want {
			t.Errorf("addr = %q, want %q", addr, want)
		}
	})

	t.Run("non_nextdns_resolver_untouched", func(t *testing.T) {
		t.Parallel()

		capMap := tailcfg.NodeCapMap{
			"nextdns:abc": []tailcfg.RawMessage{},
		}

		got := generateDNSConfig(
			mkConfig("https://dns.example.org/dns-query"),
			mkNode(),
			capMap,
		)

		want := "https://dns.example.org/dns-query"
		if addr := resolverAddr(t, got); addr != want {
			t.Errorf("non-nextdns resolver was rewritten: %q", addr)
		}
	})
}
