package internal

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Only an optional leading *. is supported; matching always respects label boundaries.
func parseRedirectDomain(pattern string) (domain string, wildcard bool, err error) {
	domain = normalizeRedirectHostname(strings.TrimSpace(pattern))
	wildcard = strings.HasPrefix(domain, "*.")
	if wildcard {
		domain = strings.TrimPrefix(domain, "*.")
	}
	if !validRedirectHostname(domain) || (wildcard && isIPAddress(domain)) {
		return "", false, fmt.Errorf("allowedRedirectDomains: invalid domain pattern %q", pattern)
	}
	return domain, wildcard, nil
}

func normalizeRedirectHostname(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

func isIPAddress(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}

func validRedirectHostname(host string) bool {
	if isIPAddress(host) {
		return !strings.Contains(host, "%")
	}
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}

func parseRedirectURL(value string) (*url.URL, error) {
	for _, ch := range value {
		if ch <= ' ' || ch == 127 || ch == '\\' {
			return nil, fmt.Errorf("invalid redirect URL")
		}
	}
	u, err := url.Parse(value)
	if err != nil || u.Opaque != "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("redirect must be an absolute HTTP(S) URL without userinfo")
	}
	if !validRedirectHostname(normalizeRedirectHostname(u.Hostname())) || strings.HasSuffix(u.Host, ":") {
		return nil, fmt.Errorf("invalid redirect hostname")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid redirect port")
		}
	}
	return u, nil
}

func redirectPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func (s Config) IsRedirectAllowed(value string) bool {
	u, err := parseRedirectURL(value)
	if err != nil {
		return false
	}
	host := normalizeRedirectHostname(u.Hostname())
	// Existing configurations default to the exact origin of defaultRedirectUrl.
	if len(s.AllowedRedirectDomains) == 0 {
		fallback, err := parseRedirectURL(s.DefaultRedirectUrl)
		return err == nil && u.Scheme == fallback.Scheme &&
			host == normalizeRedirectHostname(fallback.Hostname()) && redirectPort(u) == redirectPort(fallback)
	}
	for _, pattern := range s.AllowedRedirectDomains {
		domain, wildcard, err := parseRedirectDomain(pattern)
		if err != nil {
			continue
		}
		// Like goProxy, *.example.com includes example.com itself.
		if host == domain || wildcard && strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}
