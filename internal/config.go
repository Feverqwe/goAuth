package internal

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/gobwas/glob"
	"github.com/natefinch/atomic"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Port               int                 `yaml:"port"`
	Address            string              `yaml:"address"`
	ClientId           string              `yaml:"clientId"`
	ClientSecret       string              `yaml:"clientSecret"`
	RedirectUrl        string              `yaml:"redirectUrl"`
	DefaultRedirectUrl string              `yaml:"defaultRedirectUrl"`
	Logins             []string            `yaml:"logins"`
	CookieKey          string              `yaml:"cookieKey"`
	CookieSecret       string              `yaml:"cookieSecret"`
	CookieSalt         string              `yaml:"cookieSalt"`
	CookieMaxAge       int                 `yaml:"cookieMaxAge"`
	CookieDomain       string              `yaml:"cookieDomain"`
	TelegramBotToken   string              `yaml:"telegramBotToken"`
	TelegramChatId     string              `yaml:"telegramChatId"`
	PublicAccess       map[string][]string `yaml:"publicAccess"`

	сompiledPublicAccess map[string][]glob.Glob
}

var APP_ID = "com.rndnm.goauth"

func (s *Config) GetAddress() string {
	return s.Address + ":" + strconv.Itoa(s.Port)
}

func (s *Config) compileGlobs() error {
	s.сompiledPublicAccess = make(map[string][]glob.Glob)
	for host, patterns := range s.PublicAccess {
		for _, p := range patterns {
			g, err := glob.Compile(p)
			if err != nil {
				return fmt.Errorf("compile publicAccess glob %q for host %q: %w", p, host, err)
			}
			s.сompiledPublicAccess[host] = append(s.сompiledPublicAccess[host], g)
		}
	}
	return nil
}

func (s *Config) IsPublic(host, path string) bool {
	if globs, ok := s.сompiledPublicAccess[host]; ok {
		for _, g := range globs {
			if g.Match(path) {
				return true
			}
		}
	}
	return false
}

func randomConfigValue(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate random config value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func getNewConfig() (Config, error) {
	cookieSecret, err := randomConfigValue(32)
	if err != nil {
		return Config{}, err
	}
	cookieSalt, err := randomConfigValue(16)
	if err != nil {
		return Config{}, err
	}

	config := Config{
		Port:               80,
		RedirectUrl:        "https://example.com/callback",
		DefaultRedirectUrl: "https://example.com",
		CookieKey:          "letmein",
		CookieSecret:       cookieSecret,
		CookieSalt:         cookieSalt,
		CookieMaxAge:       7884000,
		CookieDomain:       ".example.com",
	}
	return config, nil
}

func LoadConfig() (Config, error) {
	path := getConfigPath()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(GetProfilePath(), 0750); err != nil {
				return Config{}, fmt.Errorf("create profile path: %w", err)
			}

			config, err := getNewConfig()
			if err != nil {
				return Config{}, err
			}
			if err := SaveConfig(config); err != nil {
				return Config{}, fmt.Errorf("write new config: %w", err)
			}
			return Config{}, fmt.Errorf("new config created at %q; fill in the required values and restart", path)
		}
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	if err := config.compileGlobs(); err != nil {
		return Config{}, err
	}

	return config, nil
}

func (s Config) Validate() error {
	if s.Port < 1 || s.Port > 65535 {
		return fmt.Errorf("invalid port %d", s.Port)
	}
	if strings.TrimSpace(s.ClientId) == "" {
		return fmt.Errorf("clientId is required")
	}
	if strings.TrimSpace(s.ClientSecret) == "" {
		return fmt.Errorf("clientSecret is required")
	}
	if err := validateHTTPURL("redirectUrl", s.RedirectUrl); err != nil {
		return err
	}
	if err := validateHTTPURL("defaultRedirectUrl", s.DefaultRedirectUrl); err != nil {
		return err
	}
	if len(s.Logins) == 0 {
		return fmt.Errorf("at least one login is required")
	}
	if strings.TrimSpace(s.CookieKey) == "" {
		return fmt.Errorf("cookieKey is required")
	}
	if len(s.CookieSecret) < 32 {
		return fmt.Errorf("cookieSecret must contain at least 32 characters")
	}
	if len(s.CookieSalt) < 16 {
		return fmt.Errorf("cookieSalt must contain at least 16 characters")
	}
	if s.CookieMaxAge <= 0 {
		return fmt.Errorf("cookieMaxAge must be greater than zero")
	}
	if strings.TrimSpace(s.CookieDomain) == "" {
		return fmt.Errorf("cookieDomain is required")
	}
	return nil
}

func validateHTTPURL(name, value string) error {
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("%s must be an absolute HTTP(S) URL", name)
	}
	return nil
}

func SaveConfig(config Config) error {
	path := getConfigPath()
	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}
	reader := bytes.NewReader(data)
	return atomic.WriteFile(path, reader)
}

func getConfigPath() string {
	place := GetProfilePath()
	return filepath.Join(place, "config.yaml")
}

var PROFILE_PATH_CACHE string

func GetProfilePath() string {
	if PROFILE_PATH_CACHE == "" {
		place := ""
		for _, e := range os.Environ() {
			pair := strings.SplitN(e, "=", 2)
			if pair[0] == "PROFILE_PLACE" {
				place = pair[1]
				break
			}
		}
		if place == "" {
			place = getDefaultProfilePath()
		}
		PROFILE_PATH_CACHE = place
	}
	return PROFILE_PATH_CACHE
}

func getDefaultProfilePath() string {
	place := ""
	switch runtime.GOOS {
	case "windows":
		pwd, err := os.Getwd()
		if err != nil {
			panic(err)
		}
		place = pwd
	case "darwin":
		place = os.Getenv("HOME") + "/Library/Application Support/" + APP_ID
	default:
		ex, err := os.Executable()
		if err != nil {
			panic(err)
		}
		place = filepath.Dir(ex)
	}
	return place
}

func GetStoragePath() string {
	place := GetProfilePath()
	return filepath.Join(place, "storage.json")
}
