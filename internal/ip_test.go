package internal

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestIPWhitelist(t *testing.T) {
	config := Config{IPWhitelist: []string{
		" 192.0.2.7 ", "198.51.100.42/24", "2001:db8:1::/48",
		"2001:db8:2::7", "::ffff:203.0.113.7", "::ffff:10.20.30.0/120",
	}}
	if err := config.compileIPRules(); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		ip   string
		want bool
	}{
		{"192.0.2.7", true},
		{"192.0.2.8", false},
		{"::ffff:192.0.2.7", true},
		{"198.51.100.0", true},
		{"198.51.100.255", true},
		{"198.51.101.0", false},
		{"2001:db8:1:ffff::1", true},
		{"2001:db8:2::7", true},
		{"2001:db8:2::8", false},
		{"203.0.113.7", true},
		{"203.0.113.8", false},
		{"10.20.30.255", true},
		{"10.20.31.0", false},
	} {
		t.Run(test.ip, func(t *testing.T) {
			if got := config.IsIPWhitelisted(netip.MustParseAddr(test.ip)); got != test.want {
				t.Fatalf("IsIPWhitelisted(%q) = %v, want %v", test.ip, got, test.want)
			}
		})
	}
	if config.IsIPWhitelisted(netip.Addr{}) {
		t.Fatal("invalid address must not be whitelisted")
	}
}

func TestIPWhitelistPrefixLengths(t *testing.T) {
	for _, test := range []struct {
		rule string
		ip   string
		want bool
	}{
		{"0.0.0.0/0", "203.0.113.1", true},
		{"0.0.0.0/0", "2001:db8::1", false},
		{"::/0", "2001:db8::1", true},
		{"::/0", "203.0.113.1", false},
		{"192.0.2.7/32", "192.0.2.7", true},
		{"192.0.2.7/32", "192.0.2.8", false},
		{"2001:db8::7/128", "2001:db8::7", true},
		{"2001:db8::7/128", "2001:db8::8", false},
	} {
		t.Run(test.rule+"/"+test.ip, func(t *testing.T) {
			config := Config{IPWhitelist: []string{test.rule}}
			if err := config.compileIPRules(); err != nil {
				t.Fatal(err)
			}
			if got := config.IsIPWhitelisted(netip.MustParseAddr(test.ip)); got != test.want {
				t.Fatalf("IsIPWhitelisted(%q) = %v, want %v", test.ip, got, test.want)
			}
		})
	}
}

func TestClientIP(t *testing.T) {
	for _, test := range []struct {
		name    string
		peer    string
		trusted []string
		xff     []string
		realIP  []string
		want    string // Empty means an invalid address.
	}{
		{name: "direct IPv4", peer: "192.0.2.7:1234", want: "192.0.2.7"},
		{name: "direct IPv6", peer: "[2001:db8::7]:1234", want: "2001:db8::7"},
		{name: "bare IPv6", peer: "2001:db8::7", want: "2001:db8::7"},
		{name: "mapped IPv4", peer: "[::ffff:192.0.2.7]:1234", want: "192.0.2.7"},
		{name: "invalid peer", peer: "unknown", trusted: []string{"0.0.0.0/0"}, xff: []string{"192.0.2.7"}},
		{name: "untrusted proxy", peer: "198.51.100.8:1234", trusted: []string{"10.0.0.0/24"}, xff: []string{"192.0.2.7"}, realIP: []string{"192.0.2.7"}, want: "198.51.100.8"},
		{name: "headers ignored by default", peer: "10.0.0.2:1234", xff: []string{"192.0.2.7"}, realIP: []string{"192.0.2.7"}, want: "10.0.0.2"},
		{name: "trusted proxy without headers", peer: "10.0.0.2:1234", trusted: []string{"10.0.0.0/24"}, want: "10.0.0.2"},
		{name: "single proxy", peer: "10.0.0.2:1234", trusted: []string{"10.0.0.0/24"}, xff: []string{"192.0.2.7"}, want: "192.0.2.7"},
		{name: "proxy chain", peer: "10.0.0.2:1234", trusted: []string{"10.0.0.0/24"}, xff: []string{"192.0.2.7, 10.0.0.3"}, want: "192.0.2.7"},
		{name: "separate header lines", peer: "10.0.0.2:1234", trusted: []string{"10.0.0.0/24"}, xff: []string{"192.0.2.7", "10.0.0.3"}, want: "192.0.2.7"},
		{name: "spoofed leftmost address", peer: "10.0.0.2:1234", trusted: []string{"10.0.0.0/24"}, xff: []string{"192.0.2.7, 198.51.100.8, 10.0.0.3"}, want: "198.51.100.8"},
		{name: "ignore invalid untrusted prefix", peer: "10.0.0.2:1234", trusted: []string{"10.0.0.0/24"}, xff: []string{"unknown, 198.51.100.8"}, want: "198.51.100.8"},
		{name: "all hops trusted", peer: "10.0.0.2:1234", trusted: []string{"10.0.0.0/24"}, xff: []string{"10.0.0.4, 10.0.0.3"}, want: "10.0.0.4"},
		{name: "IPv6 proxy", peer: "[2001:db8:1::2]:1234", trusted: []string{"2001:db8:1::/48"}, xff: []string{"2001:db8:2::7"}, want: "2001:db8:2::7"},
		{name: "mapped IPv4 proxy", peer: "[::ffff:10.0.0.2]:1234", trusted: []string{"10.0.0.0/24"}, xff: []string{"::ffff:192.0.2.7"}, want: "192.0.2.7"},
		{name: "real IP fallback", peer: "10.0.0.2:1234", trusted: []string{"10.0.0.2"}, realIP: []string{" 192.0.2.7 "}, want: "192.0.2.7"},
		{name: "XFF takes precedence", peer: "10.0.0.2:1234", trusted: []string{"10.0.0.2"}, xff: []string{"198.51.100.8"}, realIP: []string{"192.0.2.7"}, want: "198.51.100.8"},
		{name: "invalid XFF does not use real IP", peer: "10.0.0.2:1234", trusted: []string{"10.0.0.2"}, xff: []string{"unknown"}, realIP: []string{"192.0.2.7"}},
		{name: "invalid intermediate hop", peer: "10.0.0.2:1234", trusted: []string{"10.0.0.2"}, xff: []string{"192.0.2.7, unknown"}},
		{name: "empty XFF", peer: "10.0.0.2:1234", trusted: []string{"10.0.0.2"}, xff: []string{""}, realIP: []string{"192.0.2.7"}},
		{name: "trailing empty XFF hop", peer: "10.0.0.2:1234", trusted: []string{"10.0.0.2"}, xff: []string{"192.0.2.7,"}},
		{name: "invalid real IP", peer: "10.0.0.2:1234", trusted: []string{"10.0.0.2"}, realIP: []string{"unknown"}},
		{name: "multiple real IP lines", peer: "10.0.0.2:1234", trusted: []string{"10.0.0.2"}, realIP: []string{"192.0.2.7", "198.51.100.8"}},
		{name: "real IP list rejected", peer: "10.0.0.2:1234", trusted: []string{"10.0.0.2"}, realIP: []string{"192.0.2.7, 198.51.100.8"}},
		{name: "zone rejected", peer: "10.0.0.2:1234", trusted: []string{"10.0.0.2"}, xff: []string{"fe80::1%eth0"}},
		{name: "zone in peer rejected", peer: "[fe80::1%eth0]:1234"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := Config{TrustedProxies: test.trusted}
			if err := config.compileIPRules(); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, "/auth", nil)
			req.RemoteAddr = test.peer
			for _, value := range test.xff {
				req.Header.Add("X-Forwarded-For", value)
			}
			for _, value := range test.realIP {
				req.Header.Add("X-Real-IP", value)
			}
			got := config.ClientIP(req)
			if test.want == "" {
				if got.IsValid() {
					t.Fatalf("ClientIP() = %s, want invalid address", got)
				}
			} else if got != netip.MustParseAddr(test.want) {
				t.Fatalf("ClientIP() = %s, want %s", got, test.want)
			}
		})
	}
}
