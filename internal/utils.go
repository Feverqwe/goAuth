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
		return
	}
	tsStr := p[0]
	payload = p[2]
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return
	}
	now := time.Now().UnixMilli()
	if now-ts > int64(ttl)*1000 {
		return
	}
	ok = SignCookie(payload, tsStr, secret, salt) == payloadHash
	return
}
