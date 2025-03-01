package internal

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var RE = regexp.MustCompile(`=*$`)

func SignCookie(payload string, ts string, secret string, salt string) (payloadHash string) {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + payload + salt))
	hash := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	trimmedHash := RE.ReplaceAllString(hash, "")
	payloadHash = fmt.Sprintf("%s.%s.%s", ts, trimmedHash, payload)
	return
}

func UnsignCookie(payloadHash string, secret string, salt string, ttl int) (payload string, ok bool) {
	p := strings.SplitN(payloadHash, ".", 3)
	if len(p) != 3 {
		return payload, ok
	}
	tsStr := p[0]
	payload = p[2]
	if ts, err := strconv.ParseInt(tsStr, 10, 64); err == nil {
		now := time.Now().UnixMilli()
		if now-ts > int64(ttl)*1000 {
			ok = false
			return
		}
	} else {
		ok = false
		return
	}
	ok = SignCookie(payload, tsStr, secret, salt) == payloadHash
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
