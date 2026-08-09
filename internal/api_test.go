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
