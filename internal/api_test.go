package internal

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAuthCacheDoesNotExtendCookieLifetime(t *testing.T) {
	config := validTestConfig()
	config.CookieMaxAge = 1

	issuedAt := time.Now().Add(-500 * time.Millisecond)
	cookieValue := SignCookie("admin", strconv.FormatInt(issuedAt.UnixMilli(), 10), config.CookieSecret, config.CookieSalt)
	router := NewRouter()
	HandleApi(router, &config)

	request := func() int {
		req := httptest.NewRequest(http.MethodGet, "/auth", nil)
		req.AddCookie(&http.Cookie{Name: config.CookieKey, Value: cookieValue})
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		return response.Code
	}

	if status := request(); status != http.StatusOK {
		t.Fatalf("fresh cookie status = %d, want %d", status, http.StatusOK)
	}

	expiresAt := issuedAt.Add(time.Second)
	time.Sleep(time.Until(expiresAt) + 25*time.Millisecond)
	if status := request(); status != http.StatusUnauthorized {
		t.Fatalf("expired cached cookie status = %d, want %d", status, http.StatusUnauthorized)
	}
}

func TestHasEncodedPathSeparator(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "plain path", path: "/public/file", want: false},
		{name: "encoded space", path: "/public/hello%20world", want: false},
		{name: "encoded slash", path: "/public%2Fprivate", want: true},
		{name: "lowercase encoded slash", path: "/public%2fprivate", want: true},
		{name: "encoded backslash", path: "/public%5Cprivate", want: true},
		{name: "double encoded slash", path: "/public%252Fprivate", want: true},
		{name: "triple encoded backslash", path: "/public%25255cprivate", want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := hasEncodedPathSeparator(test.path); got != test.want {
				t.Fatalf("hasEncodedPathSeparator(%q) = %v, want %v", test.path, got, test.want)
			}
		})
	}
}

func TestAuthRejectsEncodedPathSeparatorsBeforePublicPathMatch(t *testing.T) {
	config := validTestConfig()
	config.PublicAccess = map[string][]string{
		"app.example.com": {"/public/**"},
	}
	if err := config.compileGlobs(); err != nil {
		t.Fatal(err)
	}

	router := NewRouter()
	HandleApi(router, &config)

	for _, originalURI := range []string{
		"/public%2F..%2Fprivate",
		"/public%5C..%5Cprivate",
		"/public%252F..%252Fprivate",
	} {
		t.Run(originalURI, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/auth", nil)
			req.Header.Set("X-Original-Host", "app.example.com")
			req.Header.Set("X-Original-URI", originalURI)
			response := httptest.NewRecorder()

			router.ServeHTTP(response, req)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestAuthAllowsEncodedSeparatorsInQuery(t *testing.T) {
	config := validTestConfig()
	config.PublicAccess = map[string][]string{
		"app.example.com": {"/public/**"},
	}
	if err := config.compileGlobs(); err != nil {
		t.Fatal(err)
	}

	router := NewRouter()
	HandleApi(router, &config)
	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.Header.Set("X-Original-Host", "app.example.com")
	req.Header.Set("X-Original-URI", "/public/file?next=%2Fprivate")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, strings.TrimSpace(response.Body.String()))
	}
}

func TestAuthIPWhitelist(t *testing.T) {
	config := validTestConfig()
	config.IPWhitelist = []string{"192.0.2.7", "198.51.100.0/24", "2001:db8:2::/48"}
	config.TrustedProxies = []string{"10.0.0.0/24"}
	config.PublicAccess = map[string][]string{"app.example.com": {"/public/**"}}
	if err := config.compileIPRules(); err != nil {
		t.Fatal(err)
	}
	if err := config.compileGlobs(); err != nil {
		t.Fatal(err)
	}
	router := NewRouter()
	HandleApi(router, &config)

	// Reuse the router to ensure an IP-based grant never leaks through a cache.
	for _, test := range []struct {
		name   string
		peer   string
		xff    string
		realIP string
		cookie bool
		path   string
		want   int
	}{
		{name: "single IP without cookie", peer: "192.0.2.7:1234", want: http.StatusOK},
		{name: "other IP without cookie", peer: "192.0.2.8:1234", want: http.StatusUnauthorized},
		{name: "CIDR without cookie", peer: "198.51.100.255:1234", want: http.StatusOK},
		{name: "outside CIDR", peer: "198.51.101.0:1234", want: http.StatusUnauthorized},
		{name: "IPv6 CIDR", peer: "[2001:db8:2::7]:1234", want: http.StatusOK},
		{name: "trusted proxy XFF", peer: "10.0.0.2:1234", xff: "192.0.2.7", want: http.StatusOK},
		{name: "trusted proxy real IP", peer: "10.0.0.2:1234", realIP: "192.0.2.7", want: http.StatusOK},
		{name: "trusted proxy chain", peer: "10.0.0.2:1234", xff: "192.0.2.7, 10.0.0.3", want: http.StatusOK},
		{name: "spoofed leftmost IP", peer: "10.0.0.2:1234", xff: "192.0.2.7, 203.0.113.8, 10.0.0.3", want: http.StatusUnauthorized},
		{name: "spoofed direct headers", peer: "203.0.113.8:1234", xff: "192.0.2.7", realIP: "192.0.2.7", want: http.StatusUnauthorized},
		{name: "untrusted proxy in allowed subnet", peer: "10.0.0.2:1234", xff: "203.0.113.8, 198.51.100.8", want: http.StatusOK},
		{name: "XFF takes precedence", peer: "10.0.0.2:1234", xff: "203.0.113.8", realIP: "192.0.2.7", want: http.StatusUnauthorized},
		{name: "malformed XFF", peer: "10.0.0.2:1234", xff: "192.0.2.7, unknown", realIP: "192.0.2.7", want: http.StatusUnauthorized},
		{name: "proxy without forwarding headers", peer: "10.0.0.2:1234", want: http.StatusUnauthorized},
		{name: "normal OAuth session still works", peer: "203.0.113.8:1234", cookie: true, want: http.StatusOK},
		{name: "public path still works", peer: "203.0.113.8:1234", path: "/public/file", want: http.StatusOK},
		{name: "encoded separator still rejected", peer: "192.0.2.7:1234", path: "/public%2F..%2Fprivate", want: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/auth", nil)
			req.RemoteAddr = test.peer
			if test.xff != "" {
				req.Header.Set("X-Forwarded-For", test.xff)
			}
			if test.realIP != "" {
				req.Header.Set("X-Real-IP", test.realIP)
			}
			if test.cookie {
				value := SignCookie("admin", strconv.FormatInt(time.Now().UnixMilli(), 10), config.CookieSecret, config.CookieSalt)
				req.AddCookie(&http.Cookie{Name: config.CookieKey, Value: value})
			}
			if test.path != "" {
				req.Header.Set("X-Original-Host", "app.example.com")
				req.Header.Set("X-Original-URI", test.path)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, req)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d", response.Code, test.want)
			}
		})
	}
}

func TestAuthMalformedForwardingHeaderDoesNotWhitelistProxy(t *testing.T) {
	config := validTestConfig()
	config.IPWhitelist = []string{"10.0.0.2"}
	config.TrustedProxies = []string{"10.0.0.2"}
	if err := config.compileIPRules(); err != nil {
		t.Fatal(err)
	}
	router := NewRouter()
	HandleApi(router, &config)
	for _, value := range []string{"", "unknown", "192.0.2.7,"} {
		t.Run(value, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/auth", nil)
			req.RemoteAddr = "10.0.0.2:1234"
			req.Header.Set("X-Forwarded-For", value)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, req)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
			}
		})
	}
}
