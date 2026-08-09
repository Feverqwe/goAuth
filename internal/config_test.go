package internal

import "testing"

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
