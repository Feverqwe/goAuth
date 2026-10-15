package internal

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/NYTimes/gziphandler"
	expirable "github.com/hashicorp/golang-lru/v2/expirable"
)

type JsonFailResponse struct {
	Error string `json:"error"`
}

type JsonSuccessResponse struct {
	Result any `json:"result"`
}

type authCacheEntry struct {
	authorized bool
	expiresAt  time.Time
}

const (
	oauthStateCookieName = "__Host-goauth-state"
	oauthStateTTL        = 10 * time.Minute
	oauthRequestTimeout  = 10 * time.Second
	notifyRequestTimeout = 5 * time.Second
)

func HandleApi(router *Router, config *Config) {
	apiRouter := NewRouter()
	gzipHandler := gziphandler.GzipHandler(apiRouter)

	handleAction(apiRouter, config)
	handleFobidden(apiRouter)

	router.Use(gzipHandler.ServeHTTP)
}

func handleFobidden(router *Router) {
	router.Use(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	})
}

func handleAction(router *Router, config *Config) {
	handleActionWithClient(router, config, &http.Client{Timeout: oauthRequestTimeout})
}

func handleActionWithClient(router *Router, config *Config, client *http.Client) {
	type Token struct {
		ErrorDescription string `json:"error_description"`
		Error            string `json:"error"`

		TokenType    string `json:"token_type"`
		AccessToken  string `json:"access_token"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}

	getToken := func(ctx context.Context, code string) (*Token, error) {
		p := fmt.Sprintf("grant_type=%s&code=%s",
			url.QueryEscape("authorization_code"),
			url.QueryEscape(code),
		)

		req, err := http.NewRequestWithContext(ctx, "POST", "https://oauth.yandex.ru/token", bytes.NewBuffer([]byte(p)))
		if err != nil {
			return nil, err
		}
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		b := base64.StdEncoding.EncodeToString(
			fmt.Appendf(nil, "%s:%s", config.ClientId, config.ClientSecret),
		)
		req.Header.Add("Authorization", fmt.Sprintf("Basic %s", b))

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("OAuth token endpoint returned HTTP %d", resp.StatusCode)
		}

		contentType := resp.Header.Get("Content-type")

		if !strings.HasPrefix(contentType, "application/json") {
			data, _ := io.ReadAll(resp.Body)
			return nil, errors.New(string(data))
		}

		payload, err := ParseJson[Token](resp.Body)
		if err != nil {
			return nil, err
		}

		if payload.ErrorDescription != "" {
			return nil, errors.New(payload.ErrorDescription)
		}
		if payload.Error != "" {
			return nil, errors.New(payload.Error)
		}
		if payload.AccessToken == "" {
			return nil, errors.New("OAuth token response is missing access_token")
		}

		return payload, nil
	}

	type UserInfo struct {
		Login    string `json:"login"`
		Id       string `json:"id"`
		ClientId string `json:"client_id"`
		Psuid    string `json:"psuid"`
	}

	getUserInfo := func(ctx context.Context, token string) (*UserInfo, error) {
		l := fmt.Sprintf("https://login.yandex.ru/info?format=%s",
			url.QueryEscape("json"),
		)
		req, err := http.NewRequestWithContext(ctx, "GET", l, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Add("Authorization", fmt.Sprintf("OAuth %s", token))

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("OAuth user endpoint returned HTTP %d", resp.StatusCode)
		}

		contentType := resp.Header.Get("Content-type")

		if !strings.HasPrefix(contentType, "application/json") {
			data, _ := io.ReadAll(resp.Body)
			return nil, errors.New(string(data))
		}

		payload, err := ParseJson[UserInfo](resp.Body)
		if err != nil {
			return nil, err
		}
		if payload.Login == "" {
			return nil, errors.New("OAuth user response is missing login")
		}

		return payload, nil
	}

	type TPayload struct {
		ChatId    string `json:"chat_id"`
		Text      string `json:"text"`
		ParseMode string `json:"parse_mode"`
	}

	type TResponse struct {
		Ok          bool   `json:"ok"`
		Description string `json:"description"`
	}

	sendNotify := func(ctx context.Context, i *UserInfo) (err error) {
		if config.TelegramBotToken == "" || config.TelegramChatId == "" {
			return
		}

		now := time.Now().Local()
		m := fmt.Sprintf("New login. User `%s` login into your web site on %s at %s.", i.Login, now.Format("02-01-2006"), now.Format("15:04:05"))
		j, err := json.Marshal(TPayload{
			ChatId:    config.TelegramChatId,
			Text:      m,
			ParseMode: "Markdown",
		})
		if err != nil {
			return
		}

		u := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", config.TelegramBotToken)
		req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewBuffer(j))
		if err != nil {
			return
		}
		req.Header.Add("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("Telegram endpoint returned HTTP %d", resp.StatusCode)
		}

		contentType := resp.Header.Get("Content-type")

		if !strings.HasPrefix(contentType, "application/json") {
			data, _ := io.ReadAll(resp.Body)
			err = errors.New(string(data))
			return
		}

		payload, err := ParseJson[TResponse](resp.Body)
		if err != nil {
			return
		}

		if !payload.Ok {
			err = fmt.Errorf("Telegram error: %s", payload.Description)
			return
		}

		return
	}

	cache := expirable.NewLRU[string, authCacheEntry](128, nil, time.Hour)
	publicCache := expirable.NewLRU[string, struct{}](1024, nil, time.Minute*10)
	states := expirable.NewLRU[string, string](1024, nil, oauthStateTTL)
	notifySlots := make(chan struct{}, 4)
	router.All("/auth", func(w http.ResponseWriter, r *http.Request) {
		clientIP := config.ClientIP(r)
		host := r.Header.Get("X-Original-Host")
		rawUri := r.Header.Get("X-Original-URI")
		if host != "" {
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}

			parsedUri, err := url.Parse(rawUri)
			if err != nil {
				log.Printf("Security alert: Malformed URI '%s' from %s: %v", rawUri, clientIP, err)
				w.WriteHeader(400)
				return
			}
			if parsedUri.IsAbs() || parsedUri.Host != "" || parsedUri.Fragment != "" || hasUnsafePath(parsedUri.EscapedPath()) {
				log.Printf("Security alert: Unsafe path in URI '%s' from %s", rawUri, clientIP)
				w.WriteHeader(400)
				return
			}
			path := parsedUri.Path

			cacheKey := host + "\x00" + path
			if _, found := publicCache.Get(cacheKey); found {
				w.WriteHeader(200)
				return
			}

			if config.IsPublic(host, path) || config.IsPublic("*", path) {
				publicCache.Add(cacheKey, struct{}{})
				w.WriteHeader(200)
				return
			}
		}

		if config.IsIPWhitelisted(clientIP) {
			w.WriteHeader(http.StatusOK)
			return
		}

		ok := false
		cookies := r.Cookies()
		for _, c := range cookies {
			if c.Name != config.CookieKey {
				continue
			}
			if cachedResult, found := cache.Get(c.Value); found {
				if cachedResult.expiresAt.IsZero() || time.Now().Before(cachedResult.expiresAt) {
					ok = cachedResult.authorized
					break
				}
				cache.Remove(c.Value)
			}
			entry := authCacheEntry{}
			if login, expiresAt, valid := UnsignCookieWithExpiration(c.Value, config.CookieSecret, config.CookieSalt, config.CookieMaxAge); valid {
				ok = slices.Contains(config.Logins, login)
				entry.expiresAt = expiresAt
			}
			entry.authorized = ok
			cache.Add(c.Value, entry)
			break
		}

		if ok {
			w.WriteHeader(200)
		} else {
			w.WriteHeader(401)
		}
	})

	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		origin := r.URL.Query().Get("origin")
		if origin == "" {
			origin = config.DefaultRedirectUrl
		}
		if !config.IsRedirectAllowed(origin) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		state, err := randomConfigValue(32)
		if err != nil {
			writeApiResult(w, nil, err)
			return
		}
		states.Add(state, origin)
		http.SetCookie(w, &http.Cookie{
			Name: oauthStateCookieName, Value: state, Path: "/",
			MaxAge: int(oauthStateTTL.Seconds()), Secure: true, HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		w.Header().Set("Cache-Control", "no-store")

		l := fmt.Sprintf("https://oauth.yandex.ru/authorize?response_type=%s&client_id=%s&redirect_uri=%s&state=%s",
			url.QueryEscape("code"),
			url.QueryEscape(config.ClientId),
			url.QueryEscape(config.RedirectUrl),
			url.QueryEscape(state),
		)
		w.Header().Add("Location", l)
		w.WriteHeader(307)
	})

	router.Get("/callback", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()

		code := query.Get("code")
		state := query.Get("state")
		w.Header().Set("Cache-Control", "no-store")
		cookie, err := r.Cookie(oauthStateCookieName)
		if err != nil || state == "" || !hmac.Equal([]byte(cookie.Value), []byte(state)) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		origin, found := states.Get(state)
		// Remove returns true to only one concurrent callback, making state single-use.
		if !found || !states.Remove(state) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: oauthStateCookieName, Path: "/", MaxAge: -1,
			Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
		if code == "" || !config.IsRedirectAllowed(origin) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), oauthRequestTimeout)
		defer cancel()

		p, err := getToken(ctx, code)
		if err != nil {
			writeApiResult(w, nil, err)
			return
		}

		i, err := getUserInfo(ctx, p.AccessToken)
		if err != nil {
			writeApiResult(w, nil, err)
			return
		}

		if slices.Contains(config.Logins, i.Login) {
			ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
			sigValue := SignCookie(i.Login, ts, config.CookieSecret, config.CookieSalt)
			http.SetCookie(w, &http.Cookie{
				Name: config.CookieKey, Value: sigValue, MaxAge: config.CookieMaxAge,
				Domain: config.CookieDomain, Path: "/", Secure: true, HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
			w.Header().Set("Location", origin)
			w.WriteHeader(307)

			if config.TelegramBotToken != "" && config.TelegramChatId != "" {
				select {
				case notifySlots <- struct{}{}:
					go func() {
						defer func() { <-notifySlots }()
						ctx, cancel := context.WithTimeout(context.Background(), notifyRequestTimeout)
						defer cancel()
						if err := sendNotify(ctx, i); err != nil {
							log.Println("Unable to send login notification:", err)
						}
					}()
				default:
					log.Println("Skipping login notification: all notification slots are busy")
				}
			}
			return
		}

		w.WriteHeader(403)
	})
}

func hasUnsafePath(escapedPath string) bool {
	if !strings.HasPrefix(escapedPath, "/") || hasEncodedPathSeparator(escapedPath) {
		return true
	}
	for range 8 {
		if strings.ContainsAny(escapedPath, "\\\x00\r\n") || strings.Contains(escapedPath, "//") {
			return true
		}
		for _, segment := range strings.Split(escapedPath, "/") {
			if segment == "." || segment == ".." {
				return true
			}
		}
		decoded, err := url.PathUnescape(escapedPath)
		if err != nil || decoded == escapedPath {
			return false
		}
		escapedPath = decoded
	}
	return true
}

func hasEncodedPathSeparator(escapedPath string) bool {
	for range 8 {
		lowerPath := strings.ToLower(escapedPath)
		if strings.Contains(lowerPath, "%2f") || strings.Contains(lowerPath, "%5c") {
			return true
		}

		decodedPath, err := url.PathUnescape(escapedPath)
		if err != nil || decodedPath == escapedPath {
			return false
		}
		escapedPath = decodedPath
	}

	// Excessively nested escaping is ambiguous across proxies and backends.
	return true
}

func writeApiResult(w http.ResponseWriter, result interface{}, err error) error {
	var statusCode int
	var body interface{}
	if err != nil {
		statusCode = 500
		body = JsonFailResponse{
			Error: err.Error(),
		}
	} else {
		statusCode = 200
		body = JsonSuccessResponse{
			Result: result,
		}
	}
	json, err := json.Marshal(body)
	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_, err = w.Write(json)
	}
	return err
}

func ParseJson[T any](data io.Reader) (*T, error) {
	decoder := json.NewDecoder(data)
	var payload T
	err := decoder.Decode(&payload)
	if err != nil {
		return nil, err
	}
	return &payload, nil
}
