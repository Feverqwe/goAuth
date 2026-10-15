package internal

import (
	"net/netip"
	"strings"
	"testing"
)

func TestNewConfigUsesUniqueRandomCookieCredentials(t *testing.T) {
	first, err := getNewConfig()
	if err != nil {
		t.Fatal(err)
	}
	second, err := getNewConfig()
	if err != nil {
		t.Fatal(err)
	}

	if len(first.CookieSecret) < 32 || len(first.CookieSalt) < 16 {
		t.Fatal("generated cookie credentials are too short")
	}
	if first.CookieSecret == second.CookieSecret || first.CookieSalt == second.CookieSalt {
		t.Fatal("generated cookie credentials are not unique")
	}
}

func TestConfigRejectsWeakCookieCredentials(t *testing.T) {
	config := validTestConfig()
	config.CookieSecret = "random"
	if err := config.Validate(); err == nil {
		t.Fatal("expected weak cookieSecret to be rejected")
	}

	config = validTestConfig()
	config.CookieSalt = "short"
	if err := config.Validate(); err == nil {
		t.Fatal("expected weak cookieSalt to be rejected")
	}
}

func TestConfigRejectsInvalidIPRules(t *testing.T) {
	for _, field := range []string{"ipWhitelist", "trustedProxies"} {
		for _, value := range []string{"", " ", "example.com", "192.0.2.999", "192.0.2.0/33", "2001:db8::/129", "fe80::1%eth0", "::ffff:192.0.2.0/80", "192.0.2.7:80"} {
			t.Run(field+"/"+value, func(t *testing.T) {
				config := validTestConfig()
				if field == "ipWhitelist" {
					config.IPWhitelist = []string{value}
				} else {
					config.TrustedProxies = []string{value}
				}
				if err := config.Validate(); err == nil || !strings.Contains(err.Error(), field) {
					t.Fatalf("Validate() = %v, want error identifying %s", err, field)
				}
			})
		}
	}
}

func TestLoadConfigCompilesIPRules(t *testing.T) {
	previousPath := PROFILE_PATH_CACHE
	PROFILE_PATH_CACHE = ""
	t.Cleanup(func() { PROFILE_PATH_CACHE = previousPath })
	t.Setenv("PROFILE_PLACE", t.TempDir())
	config := validTestConfig()
	config.IPWhitelist = []string{"192.0.2.0/24", "2001:db8::7"}
	config.TrustedProxies = []string{"10.0.0.2"}
	config.AllowedRedirectDomains = []string{"*.example.com"}
	if err := SaveConfig(config); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.IsIPWhitelisted(netip.MustParseAddr("192.0.2.7")) || !loaded.IsIPWhitelisted(netip.MustParseAddr("2001:db8::7")) {
		t.Fatal("loaded whitelist is not compiled")
	}
	if !containsIP(loaded.compiledTrustedProxies, netip.MustParseAddr("10.0.0.2")) {
		t.Fatal("loaded trusted proxies are not compiled")
	}
	if !loaded.IsRedirectAllowed("https://app.example.com/private") || loaded.IsRedirectAllowed("https://example.com.evil.org") {
		t.Fatal("loaded redirect domain rules were not preserved")
	}
}

func validTestConfig() Config {
	return Config{
		Port:               8044,
		ClientId:           "client-id",
		ClientSecret:       "client-secret",
		RedirectUrl:        "https://auth.example.com/callback",
		DefaultRedirectUrl: "https://example.com",
		Logins:             []string{"admin"},
		CookieKey:          "auth_token",
		CookieSecret:       "0123456789abcdef0123456789abcdef",
		CookieSalt:         "0123456789abcdef",
		CookieMaxAge:       3600,
		CookieDomain:       ".example.com",
	}
}
