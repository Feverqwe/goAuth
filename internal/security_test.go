package internal

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testTransport func(*http.Request) (*http.Response, error)

func (f testTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func providerResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func testOAuthRouter(config *Config, transport testTransport) *Router {
	router := NewRouter()
	handleActionWithClient(router, config, &http.Client{Transport: transport, Timeout: oauthRequestTimeout})
	return router
}

func startTestOAuth(t *testing.T, router *Router, origin string) (string, *http.Cookie) {
	t.Helper()
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/?origin="+url.QueryEscape(origin), nil))
	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("start OAuth status = %d", w.Code)
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state := u.Query().Get("state")
	if len(state) < 32 || strings.Contains(state, "origin=") {
		t.Fatalf("invalid state %q", state)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == oauthStateCookieName {
			if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Domain != "" || c.Path != "/" || c.MaxAge != 600 || c.Value != state {
				t.Fatalf("unsafe state cookie: %+v", c)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("OAuth redirect is cacheable")
			}
			return state, c
		}
	}
	t.Fatal("missing state cookie")
	return "", nil
}

func callbackRequest(state string, cookie *http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/callback?code=test-code&state="+url.QueryEscape(state), nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	return r
}

func sessionCookie(w *httptest.ResponseRecorder, key string) *http.Cookie {
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == key && cookie.MaxAge > 0 {
			return cookie
		}
	}
	return nil
}

func TestAuthRejectsAmbiguousPaths(t *testing.T) {
	config := validTestConfig()
	config.PublicAccess = map[string][]string{"app.example.com": {"/public/**"}}
	if err := config.compileGlobs(); err != nil {
		t.Fatal(err)
	}
	router := NewRouter()
	HandleApi(router, &config)
	paths := []string{
		"/public/../private", "/public/./private", "/public/%2e%2e/private",
		"/public/.%2E/private", "/public/%252e%252e/private", "/public//private",
		"/public/..\\private", "/public/%00private", "https://app.example.com/public/file",
		"//app.example.com/public/file", "/public/file#fragment", "public/file", "",
	}
	nested := "%2e%2e"
	for range 8 {
		nested = strings.ReplaceAll(nested, "%", "%25")
	}
	paths = append(paths, "/public/"+nested+"/private")
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/auth", nil)
			r.Header.Set("X-Original-Host", "app.example.com")
			r.Header.Set("X-Original-URI", path)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("unsafe path %q status = %d", path, w.Code)
			}
		})
	}
	for _, path := range []string{"/public/file.txt", "/public/hello%20world", "/public/file?next=../private"} {
		r := httptest.NewRequest(http.MethodGet, "/auth", nil)
		r.Header.Set("X-Original-Host", "app.example.com")
		r.Header.Set("X-Original-URI", path)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("safe path %q status = %d", path, w.Code)
		}
	}
}

func TestOAuthRejectsUnboundStateBeforeContactingProvider(t *testing.T) {
	config := validTestConfig()
	var calls atomic.Int32
	router := testOAuthRouter(&config, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return providerResponse(`{"access_token":"test-token"}`), nil
	})
	for _, name := range []string{"missing state", "missing cookie", "wrong browser", "tampered state", "unknown state", "legacy state", "missing code"} {
		t.Run(name, func(t *testing.T) {
			state, cookie := startTestOAuth(t, router, config.DefaultRedirectUrl)
			switch name {
			case "missing state":
				state = ""
			case "missing cookie":
				cookie = nil
			case "wrong browser":
				cookie.Value = "another-browser"
			case "tampered state":
				state += "tampered"
			case "unknown state":
				state = "unknown"
				cookie.Value = state
			case "legacy state":
				state = "origin=https://evil.org"
				cookie.Value = state
			}
			r := callbackRequest(state, cookie)
			if name == "missing code" {
				r.URL.RawQuery = "state=" + url.QueryEscape(state)
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest || sessionCookie(w, config.CookieKey) != nil {
				t.Fatalf("invalid callback status = %d, cookies = %v", w.Code, w.Result().Cookies())
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("provider called %d times for invalid callbacks", calls.Load())
	}
}

func TestOAuthStateIsSingleUseAndPreservesOrigin(t *testing.T) {
	config := validTestConfig()
	config.AllowedRedirectDomains = []string{"*.rndnm.com"}
	var calls atomic.Int32
	router := testOAuthRouter(&config, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if deadline, ok := r.Context().Deadline(); !ok || time.Until(deadline) > oauthRequestTimeout {
			t.Error("OAuth request missing bounded deadline")
		}
		if r.URL.Host == "login.yandex.ru" {
			return providerResponse(`{"login":"admin"}`), nil
		}
		return providerResponse(`{"access_token":"test-token"}`), nil
	})
	origin := "https://app.rndnm.com/private?a=1&b=2#section"
	state, cookie := startTestOAuth(t, router, origin)
	otherState, _ := startTestOAuth(t, router, origin)
	if otherState == state {
		t.Fatal("state reused between login attempts")
	}
	// Concurrent callbacks must not both exchange a code or issue a session.
	results := make(chan *httptest.ResponseRecorder, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			router.ServeHTTP(w, callbackRequest(state, cookie))
			results <- w
		}()
	}
	wg.Wait()
	close(results)
	var successes, failures int
	for w := range results {
		if w.Code == http.StatusBadRequest {
			failures++
			continue
		}
		if w.Code != http.StatusTemporaryRedirect || w.Header().Get("Location") != origin {
			t.Fatalf("callback status = %d, location = %q", w.Code, w.Header().Get("Location"))
		}
		c := sessionCookie(w, config.CookieKey)
		if c == nil || !c.Secure || !c.HttpOnly {
			t.Fatal("missing secure session cookie")
		}
		if login, ok := UnsignCookie(c.Value, config.CookieSecret, config.CookieSalt, config.CookieMaxAge); !ok || login != "admin" {
			t.Fatal("invalid issued session")
		}
		cleared := false
		for _, c := range w.Result().Cookies() {
			if c.Name == oauthStateCookieName && c.MaxAge < 0 {
				cleared = true
			}
		}
		if !cleared {
			t.Fatal("state cookie not cleared")
		}
		successes++
	}
	if successes != 1 || failures != 1 || calls.Load() != 2 {
		t.Fatalf("successes=%d failures=%d provider calls=%d", successes, failures, calls.Load())
	}
}

func TestOAuthRejectsExternalOriginAndRevalidatesCallback(t *testing.T) {
	config := validTestConfig()
	config.AllowedRedirectDomains = []string{"*.rndnm.com"}
	var calls atomic.Int32
	router := testOAuthRouter(&config, func(r *http.Request) (*http.Response, error) { calls.Add(1); return providerResponse(`{}`), nil })
	for _, origin := range []string{"https://evil.org", "https://rndnm.com.evil.org", "https://rndnm.com@evil.org", "//evil.org"} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/?origin="+url.QueryEscape(origin), nil))
		if w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" || len(w.Result().Cookies()) != 0 {
			t.Errorf("untrusted origin %q accepted", origin)
		}
	}
	state, cookie := startTestOAuth(t, router, "https://app.rndnm.com")
	config.AllowedRedirectDomains = []string{"example.com"}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, callbackRequest(state, cookie))
	if w.Code != http.StatusBadRequest || calls.Load() != 0 {
		t.Fatal("callback did not revalidate stored origin")
	}
}

func TestOAuthRequestsRespectCancellation(t *testing.T) {
	config := validTestConfig()
	started := make(chan struct{})
	router := testOAuthRouter(&config, func(r *http.Request) (*http.Response, error) {
		close(started)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	state, cookie := startTestOAuth(t, router, config.DefaultRedirectUrl)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, callbackRequest(state, cookie).WithContext(ctx))
		done <- w
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("provider request did not start")
	}
	cancel()
	select {
	case w := <-done:
		if w.Code != http.StatusInternalServerError || sessionCookie(w, config.CookieKey) != nil {
			t.Fatalf("cancelled callback status = %d", w.Code)
		}
	case <-time.After(time.Second):
		t.Fatal("callback ignored request cancellation")
	}
}

func TestTelegramDoesNotBlockLoginAndHasDeadline(t *testing.T) {
	config := validTestConfig()
	config.TelegramBotToken = "test"
	config.TelegramChatId = "test"
	started := make(chan struct{})
	finished := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	router := testOAuthRouter(&config, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "api.telegram.org" {
			defer close(finished)
			if deadline, ok := r.Context().Deadline(); !ok || time.Until(deadline) > notifyRequestTimeout {
				t.Error("Telegram request missing bounded deadline")
			}
			close(started)
			select {
			case <-release:
			case <-r.Context().Done():
			}
			return providerResponse(`{"ok":true}`), nil
		}
		if r.URL.Host == "login.yandex.ru" {
			return providerResponse(`{"login":"admin"}`), nil
		}
		return providerResponse(`{"access_token":"test-token"}`), nil
	})
	state, cookie := startTestOAuth(t, router, config.DefaultRedirectUrl)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { w := httptest.NewRecorder(); router.ServeHTTP(w, callbackRequest(state, cookie)); done <- w }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("notification did not start")
	}
	select {
	case w := <-done:
		if w.Code != http.StatusTemporaryRedirect || sessionCookie(w, config.CookieKey) == nil {
			t.Fatalf("callback status = %d", w.Code)
		}
	case <-time.After(time.Second):
		t.Fatal("login blocked on Telegram")
	}
	// Release the transport and wait before the test ends, including on failures.
	t.Cleanup(func() {
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Error("notification did not finish")
		}
	})
}

func TestOAuthRejectsInvalidProviderResponses(t *testing.T) {
	for _, name := range []string{"token status", "missing token", "user status", "missing login", "denied login"} {
		t.Run(name, func(t *testing.T) {
			config := validTestConfig()
			router := testOAuthRouter(&config, func(r *http.Request) (*http.Response, error) {
				body := `{"access_token":"test-token"}`
				status := http.StatusOK
				if r.URL.Host == "login.yandex.ru" {
					body = `{"login":"admin"}`
					if name == "user status" {
						status = http.StatusUnauthorized
					}
					if name == "missing login" {
						body = `{}`
					}
					if name == "denied login" {
						body = `{"login":"other-user"}`
					}
				} else {
					if name == "token status" {
						status = http.StatusBadRequest
					}
					if name == "missing token" {
						body = `{}`
					}
				}
				resp := providerResponse(body)
				resp.StatusCode = status
				return resp, nil
			})
			state, cookie := startTestOAuth(t, router, config.DefaultRedirectUrl)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, callbackRequest(state, cookie))
			want := http.StatusInternalServerError
			if name == "denied login" {
				want = http.StatusForbidden
			}
			if w.Code != want || sessionCookie(w, config.CookieKey) != nil {
				t.Fatalf("callback status = %d, want %d without session", w.Code, want)
			}
			w = httptest.NewRecorder()
			router.ServeHTTP(w, callbackRequest(state, cookie))
			if w.Code != http.StatusBadRequest {
				t.Fatal("failed login state was reusable")
			}
		})
	}
}
