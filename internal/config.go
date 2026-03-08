package internal

import (
	"bytes"
	"log"
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
	Name               string              `yaml:"name"`
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

func (s *Config) GetBrowserAddress() string {
	addr := s.Address
	if addr == "" {
		addr = "127.0.0.1"
	}
	return "http://" + addr + ":" + strconv.Itoa(s.Port)
}

func getNewConfig() Config {
	var config = Config{
		Port:               80,
		Name:               "Auth",
		RedirectUrl:        "https://example.com/callback",
		DefaultRedirectUrl: "https://example.com",
		CookieKey:          "letmein",
		CookieSecret:       "random",
		CookieMaxAge:       7884000,
		CookieDomain:       ".example.com",
	}
	return config
}

func LoadConfig() Config {
	newConfig := getNewConfig()
	config := newConfig

	path := getConfigPath()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(GetProfilePath(), 0750); err != nil {
				log.Println("Create profile path error", err)
			}

			if err := SaveConfig(config); err != nil {
				log.Println("Write new config error", err)
			}
		}
	} else {
		if err := yaml.Unmarshal(data, &config); err != nil {
			log.Println("Load config error", err)
		}
	}

	config.CompileGlobs()

	return config
}

func SaveConfig(config Config) error {
	path := getConfigPath()
	if data, err := yaml.Marshal(config); err == nil {
		reader := bytes.NewReader(data)
		err = atomic.WriteFile(path, reader)
		return err
	}
	return nil
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

func (s *Config) CompileGlobs() {
	s.сompiledPublicAccess = make(map[string][]glob.Glob)
	for host, patterns := range s.PublicAccess {
		for _, p := range patterns {
			g, err := glob.Compile(p)
			if err != nil {
				log.Printf("Error compiling glob '%s' for host '%s': %v", p, host, err)
				continue
			}
			s.сompiledPublicAccess[host] = append(s.сompiledPublicAccess[host], g)
		}
	}
}
