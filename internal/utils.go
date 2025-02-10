package internal

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

func EscapeHtmlInJson(content string) string {
	content = strings.Replace(content, ">", "\\u003e", -1)
	content = strings.Replace(content, "&", "\\u0026", -1)
	content = strings.Replace(content, "<", "\\u003c", -1)
	content = strings.Replace(content, "\u2028", "\\u2028", -1)
	content = strings.Replace(content, "\u2029", "\\u2029", -1)
	return content
}

var RE = regexp.MustCompile(`=*$`)

func SignCookie(value string, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(value))
	hash := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	trimmedHash := RE.ReplaceAllString(hash, "")
	return fmt.Sprintf("%s.%s", value, trimmedHash)
}

func UnsignCookie(valueHash string, secret string) (string, bool) {
	p := strings.SplitN(valueHash, ".", 2)
	if len(p) != 2 {
		return "", false
	}
	value := p[0]
	ok := SignCookie(value, secret) == valueHash
	return value, ok
}
