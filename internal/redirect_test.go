package internal

import (
	"strings"
	"testing"
)

func TestRedirectDomainPatterns(t *testing.T) {
	config := validTestConfig()
	config.AllowedRedirectDomains = []string{"*.rndnm.com", "EXAMPLE.COM", "localhost", "::1"}
	for _, test := range []struct {
		url  string
		want bool
	}{
		{"https://rndnm.com", true},
		{"https://app.rndnm.com/path?a=1&b=2#part", true},
		{"https://one.two.rndnm.com", true},
		{"https://APP.RNDNM.COM.:8443/path", true},
		{"http://app.rndnm.com:8080", true},
		{"https://example.com", true},
		{"http://localhost:8080", true},
		{"http://[::1]:8080", true},
		{"https://sub.example.com", false},
		{"https://evilrndnm.com", false},
		{"https://rndnm.com.evil.org", false},
		{"https://app.rndnm.com.evil.org", false},
		{"https://rndnm.com@evil.org", false},
		{"https://user@app.rndnm.com", false},
		{"https://rndnm.com\\@evil.org", false},
		{"https://rndnm.com%2eevil.org", false},
		{"https://rndnm.com..", false},
		{"https://rndnm.com:0", false},
		{"https://rndnm.com:65536", false},
		{"https://rndnm.com:", false},
		{"//rndnm.com/path", false},
		{"/path", false},
		{"javascript:alert(1)", false},
		{"https:////rndnm.com", false},
		{"https://rndnm.com\r\nX-Test: bad", false},
		{"https://рndnm.com", false},
	} {
		t.Run(test.url, func(t *testing.T) {
			if got := config.IsRedirectAllowed(test.url); got != test.want {
				t.Fatalf("IsRedirectAllowed(%q) = %v, want %v", test.url, got, test.want)
			}
		})
	}
}

func TestRedirectDefaultsToConfiguredOrigin(t *testing.T) {
	config := validTestConfig()
	for _, test := range []struct {
		url  string
		want bool
	}{
		{"https://example.com/private?x=1", true},
		{"https://EXAMPLE.COM:443/", true},
		{"http://example.com/", false},
		{"https://example.com:8443/", false},
		{"https://app.example.com/", false},
	} {
		if got := config.IsRedirectAllowed(test.url); got != test.want {
			t.Errorf("IsRedirectAllowed(%q) = %v, want %v", test.url, got, test.want)
		}
	}
}

func TestConfigValidatesRedirectDomains(t *testing.T) {
	for _, pattern := range []string{"", "*", "*rndnm.com", "api.*.rndnm.com", "https://rndnm.com", "rndnm.com/path", "rndnm.com:443", "*.127.0.0.1", ".rndnm.com", "rndnm..com", "!rndnm.com"} {
		t.Run(pattern, func(t *testing.T) {
			config := validTestConfig()
			config.AllowedRedirectDomains = []string{pattern}
			if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "allowedRedirectDomains") {
				t.Fatalf("Validate() = %v, want domain pattern error", err)
			}
		})
	}
	config := validTestConfig()
	config.DefaultRedirectUrl = "https://rndnm.com"
	config.AllowedRedirectDomains = []string{"*.rndnm.com"}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	config.DefaultRedirectUrl = "https://evil.org"
	if err := config.Validate(); err == nil {
		t.Fatal("disallowed default redirect accepted")
	}
}
