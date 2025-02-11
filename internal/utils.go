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

func SignCookie(payload string, ts string, secret string, salt string) (payloadHash string) {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload + salt))
	hash := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	trimmedHash := RE.ReplaceAllString(hash, "")
	payloadHash = fmt.Sprintf("%s.%s.%s", ts, payload, trimmedHash)
	return
}

func UnsignCookie(payloadHash string, secret string, salt string) (payload string, ok bool) {
	p := strings.SplitN(payloadHash, ".", 3)
	if len(p) != 3 {
		return payload, ok
	}
	ts := p[0]
	payload = p[1]
	ok = SignCookie(payload, ts, secret, salt) == payloadHash
	return
}

func Contains(arr []string, value string) bool {
	for _, i := range arr {
		if i == value {
			return true
		}
	}
	return false
}
