package internal

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

var RE = regexp.MustCompile(`=*$`)

func SignCookie(value string, secret string, salt string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(value + salt))
	hash := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	trimmedHash := RE.ReplaceAllString(hash, "")
	hashValue := fmt.Sprintf("%s.%s", value, trimmedHash)
	return hashValue
}

func UnsignCookie(valueHash string, secret string, salt string) (string, bool) {
	p := strings.SplitN(valueHash, ".", 2)
	if len(p) != 2 {
		return "", false
	}
	value := p[0]
	ok := SignCookie(value, secret, salt) == valueHash
	return value, ok
}

func Contains(arr []string, value string) bool {
	for _, i := range arr {
		if i == value {
			return true
		}
	}
	return false
}
