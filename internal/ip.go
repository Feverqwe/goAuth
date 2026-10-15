package internal

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
)

// parseIPRanges accepts individual IPv4/IPv6 addresses and CIDR networks.
// IPv4-mapped IPv6 addresses are normalized to IPv4 for consistent matching.
func parseIPRanges(name string, values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		entry := strings.TrimSpace(value)
		var prefix netip.Prefix
		if strings.Contains(entry, "/") {
			parsed, err := netip.ParsePrefix(entry)
			if err != nil {
				return nil, fmt.Errorf("%s: invalid IP or CIDR %q: %w", name, value, err)
			}
			prefix = parsed
			if prefix.Addr().Is4In6() {
				if prefix.Bits() < 96 {
					return nil, fmt.Errorf("%s: IPv4-mapped CIDR %q must have a prefix length of at least 96", name, value)
				}
				prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
			}
		} else {
			addr, err := netip.ParseAddr(entry)
			if err != nil || addr.Zone() != "" {
				return nil, fmt.Errorf("%s: invalid IP or CIDR %q", name, value)
			}
			addr = addr.Unmap()
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

func (s *Config) compileIPRules() error {
	whitelist, err := parseIPRanges("ipWhitelist", s.IPWhitelist)
	if err != nil {
		return err
	}
	proxies, err := parseIPRanges("trustedProxies", s.TrustedProxies)
	if err != nil {
		return err
	}
	s.compiledIPWhitelist = whitelist
	s.compiledTrustedProxies = proxies
	return nil
}

func containsIP(prefixes []netip.Prefix, addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (s *Config) IsIPWhitelisted(addr netip.Addr) bool {
	return containsIP(s.compiledIPWhitelist, addr)
}

// ClientIP trusts forwarding headers only from configured proxy addresses.
// Invalid headers produce an invalid address, never a whitelist match.
func (s *Config) ClientIP(r *http.Request) netip.Addr {
	peer := parseIP(r.RemoteAddr)
	if !containsIP(s.compiledTrustedProxies, peer) {
		return peer
	}

	if values := r.Header.Values("X-Forwarded-For"); len(values) > 0 {
		// Multiple header lines form the same chain as a comma-separated header.
		chain := strings.Split(strings.Join(values, ","), ",")
		addr := peer
		for i := len(chain) - 1; i >= 0; i-- {
			if !containsIP(s.compiledTrustedProxies, addr) {
				return addr
			}
			addr = parseForwardedIP(chain[i])
			if !addr.IsValid() {
				return netip.Addr{}
			}
		}
		return addr
	}

	if values := r.Header.Values("X-Real-IP"); len(values) > 0 {
		if len(values) != 1 {
			return netip.Addr{}
		}
		return parseForwardedIP(values[0])
	}
	return peer
}

func parseIP(value string) netip.Addr {
	if addrPort, err := netip.ParseAddrPort(value); err == nil {
		if addrPort.Addr().Zone() == "" {
			return addrPort.Addr().Unmap()
		}
		return netip.Addr{}
	}
	return parseForwardedIP(value)
}

func parseForwardedIP(value string) netip.Addr {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}
	}
	return addr.Unmap()
}
