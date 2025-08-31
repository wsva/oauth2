package main

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"time"
)

type CodeInfo struct {
	Scope       string
	ClientID    string
	AccountID   string
	Challenge   string
	Code        string
	ExpireAt    time.Time
	ParentToken string // access_token of OAuth2
}

type CodeMap struct {
	Map map[string]*CodeInfo
}

func (c *CodeMap) Add(ci *CodeInfo) {
	if c.Map == nil {
		c.Map = make(map[string]*CodeInfo)
	}
	c.Map[ci.Code] = ci
}

func (c *CodeMap) VerifyChallenge(code, verifier string) (*CodeInfo, bool) {
	if c.Map == nil {
		c.Map = make(map[string]*CodeInfo)
	}
	codeObj, ok := c.Map[code]
	if !ok {
		return nil, false
	}

	defer delete(c.Map, code)

	if codeObj.ExpireAt.Before(time.Now()) {
		return nil, false
	}

	s256 := sha256.Sum256([]byte(verifier))
	// trim padding, but why?
	challenge := strings.TrimRight(base64.URLEncoding.EncodeToString(s256[:]), "=")
	if challenge == strings.TrimRight(codeObj.Challenge, "=") {
		return codeObj, true
	}
	return nil, false
}
