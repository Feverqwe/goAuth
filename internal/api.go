package internal

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/NYTimes/gziphandler"
	"github.com/google/uuid"
)

type JsonFailResponse struct {
	Error string `json:"error"`
}

type JsonSuccessResponse struct {
	Result interface{} `json:"result"`
}

func HandleApi(router *Router, config *Config, storage *Storage) {
	apiRouter := NewRouter()
	gzipHandler := gziphandler.GzipHandler(apiRouter)

	handleAction(apiRouter, config, storage)
	handleFobidden(apiRouter)

	router.All("^/", gzipHandler.ServeHTTP)
}

func handleFobidden(router *Router) {
	router.Use(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	})
}

func handleAction(router *Router, config *Config, storage *Storage) {
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
		b := base64.StdEncoding.EncodeToString([]byte(
			fmt.Sprintf("%s:%s", config.ClientId, config.ClientSecter),
		))
		req.Header.Add("Authorization", fmt.Sprintf("Basic %s", b))

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		contentType := resp.Header.Get("Content-type")

		if strings.HasPrefix(contentType, "text/plain") {
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
		Login string `json:"login"`
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

		if strings.HasPrefix(contentType, "text/plain") {
			data, _ := io.ReadAll(resp.Body)
			return nil, errors.New(string(data))
		}

		payload, err := ParseJson[UserInfo](resp.Body)
		if err != nil {
			return nil, err
		}

		return payload, nil
	}

	router.All("/auth", func(w http.ResponseWriter, r *http.Request) {
		ok := false
		cookies := r.Cookies()
		for _, c := range cookies {
			if c.Name != config.CookieKey {
				continue
			}
			value, isOk := UnsignCookie(c.Value, config.CookieSecret)
			if !isOk {
				break
			}
			ok = storage.HasKey(value)
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

		if i.Login == config.Login {
			value := SignCookie(uuid.New().String(), config.CookieSecret)
			storage.SetKey(value, config.Login)
			w.Header().Add("Set-Cookie", fmt.Sprintf("%s=%s;Max-Age=%s;Domain=%s;Path=/;Secure;HttpOnly", config.CookieKey, value, strconv.Itoa(config.CookieMaxAge), config.CookieDomain))
			w.Header().Add("Location", stateQuery.Get("origin"))
			w.WriteHeader(307)
			return
		}

		w.WriteHeader(403)
	})
}

type ActionAny[T any] func() (T, error)

func apiCall[T any](w http.ResponseWriter, action ActionAny[T]) {
	result, err := action()
	err = writeApiResult(w, result, err)
	if err != nil {
		panic(err)
	}
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

func sendStatus(w http.ResponseWriter, statusCode int) {
	w.WriteHeader(statusCode)
	_, err := w.Write(make([]byte, 0))
	if err != nil {
		panic(err)
	}
}

func setValue[T int64 | string | bool](val *T, def T) T {
	if val == nil {
		return def
	}
	return *val
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
