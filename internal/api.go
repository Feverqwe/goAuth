package internal

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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
	type Token struct {
		ErrorDescription string `json:"error_description"`
		Error            string `json:"error"`

		TokenType    string `json:"token_type"`
		AccessToken  string `json:"access_token"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}

	getToken := func(code string) (*Token, error) {
		p := fmt.Sprintf("grant_type=%s&code=%s",
			url.QueryEscape("authorization_code"),
			url.QueryEscape(code),
		)

		req, err := http.NewRequest("POST", "https://oauth.yandex.ru/token", bytes.NewBuffer([]byte(p)))
		if err != nil {
			return nil, err
		}
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		b := base64.StdEncoding.EncodeToString(
			fmt.Appendf(nil, "%s:%s", config.ClientId, config.ClientSecter),
		)
		req.Header.Add("Authorization", fmt.Sprintf("Basic %s", b))

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

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

		return payload, nil
	}

	type UserInfo struct {
		Login    string `json:"login"`
		Id       string `json:"id"`
		ClientId string `json:"client_id"`
		Psuid    string `json:"psuid"`
	}

	getUserInfo := func(token string) (*UserInfo, error) {
		l := fmt.Sprintf("https://login.yandex.ru/info?format=%s",
			url.QueryEscape("json"),
		)
		req, err := http.NewRequest("GET", l, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Add("Authorization", fmt.Sprintf("OAuth %s", token))

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		contentType := resp.Header.Get("Content-type")

		if !strings.HasPrefix(contentType, "application/json") {
			data, _ := io.ReadAll(resp.Body)
			return nil, errors.New(string(data))
		}

		payload, err := ParseJson[UserInfo](resp.Body)
		if err != nil {
			return nil, err
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

	sendNotify := func(i *UserInfo) (err error) {
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
		req, err := http.NewRequest("POST", u, bytes.NewBuffer(j))
		if err != nil {
			return
		}
		req.Header.Add("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()

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
			err = errors.New(fmt.Sprintf("Telegram error: %s", payload.Description))
			return
		}

		return
	}

	cache := expirable.NewLRU[string, bool](128, nil, time.Hour)
	router.All("/auth", func(w http.ResponseWriter, r *http.Request) {
		ok := false
		cookies := r.Cookies()
		for _, c := range cookies {
			if c.Name != config.CookieKey {
				continue
			}
			if cachedResult, found := cache.Get(c.Value); found {
				ok = cachedResult
				break
			}
			if login, valid := UnsignCookie(c.Value, config.CookieSecret, config.CookieSalt, config.CookieMaxAge); valid {
				ok = slices.Contains(config.Logins, login)
			}
			cache.Add(c.Value, ok)
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
			origin = config.DefultRedirectUrl
		}
		if origin == "" {
			w.WriteHeader(403)
			return
		}

		l := fmt.Sprintf("https://oauth.yandex.ru/authorize?response_type=%s&client_id=%s&redirect_uri=%s&state=%s",
			url.QueryEscape("code"),
			url.QueryEscape(config.ClientId),
			url.QueryEscape(config.RedirectUrl),
			url.QueryEscape(
				fmt.Sprintf("origin=%s", url.QueryEscape(origin)),
			),
		)
		w.Header().Add("Location", l)
		w.WriteHeader(307)
	})

	router.Get("/callback", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()

		code := query.Get("code")
		state := query.Get("state")

		stateQuery, err := url.ParseQuery(state)
		if err != nil {
			writeApiResult(w, nil, err)
			return
		}

		p, err := getToken(code)
		if err != nil {
			writeApiResult(w, nil, err)
			return
		}

		i, err := getUserInfo(p.AccessToken)
		if err != nil {
			writeApiResult(w, nil, err)
			return
		}

		if slices.Contains(config.Logins, i.Login) {
			ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
			sigValue := SignCookie(i.Login, ts, config.CookieSecret, config.CookieSalt)
			w.Header().Add("Set-Cookie", fmt.Sprintf("%s=%s;Max-Age=%s;Domain=%s;Path=/;Secure;HttpOnly", config.CookieKey, sigValue, strconv.Itoa(config.CookieMaxAge), config.CookieDomain))
			w.Header().Add("Location", stateQuery.Get("origin"))
			w.WriteHeader(307)

			if err := sendNotify(i); err != nil {
				log.Println("Unable send notiy", err)
			}
			return
		}

		w.WriteHeader(403)
	})
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
