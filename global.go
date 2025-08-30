package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/tidwall/pretty"
	wl_crypto "github.com/wsva/lib_go/crypto"
	wl_fs "github.com/wsva/lib_go/fs"
	wl_http "github.com/wsva/lib_go/http"
	wl_db "github.com/wsva/lib_go_db"
)

type MainConfig struct {
	ListenList   []wl_http.ListenInfo `json:"ListenList"`
	DatabaseURL  wl_db.URL            `json:"DatabaseURL"`
	RSAPubFile   string               `json:"RSAPubFile"`
	RSAKeyFile   string               `json:"RSAKeyFile"`
	HttpsCrtFile string               `json:"HttpsCrtFile"`
	HttpsKeyFile string               `json:"HttpsKeyFile"`
	AESKey       string               `json:"AESKey"`
	AESIV        string               `json:"AESIV"`
}

var (
	Basepath       = ""
	MainConfigFile = path.Join("config", "auth_service_config.json")
)

var mainConfig MainConfig
var dbConfig *wl_db.Config

var loginAudit *LoginAudit

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
)

var codeMap *CodeMap

func initGlobals() error {
	basepath, err := wl_fs.GetExecutableFullpath()
	if err != nil {
		return err
	}
	Basepath = basepath
	MainConfigFile = path.Join(basepath, MainConfigFile)

	contentBytes, err := os.ReadFile(MainConfigFile)
	if err != nil {
		return err
	}
	err = json.Unmarshal(contentBytes, &mainConfig)
	if err != nil {
		return err
	}

	if wl_crypto.IsAES256Text(string(mainConfig.DatabaseURL)) {
		text, err := wl_crypto.AES256Decrypt(mainConfig.AESKey, mainConfig.AESIV, string(mainConfig.DatabaseURL))
		if err != nil {
			return err
		}
		mainConfig.DatabaseURL = wl_db.URL(text)
		dbConfig, err = mainConfig.DatabaseURL.Parse()
		if err != nil {
			return err
		}
		err = dbConfig.InitDB()
		if err != nil {
			return err
		}
	} else if mainConfig.DatabaseURL != "" {
		dbConfig, err = mainConfig.DatabaseURL.Parse()
		if err != nil {
			return err
		}
		err = dbConfig.InitDB()
		if err != nil {
			return err
		}

		ctext, err := wl_crypto.AES256Encrypt(mainConfig.AESKey, mainConfig.AESIV, string(mainConfig.DatabaseURL))
		if err != nil {
			return err
		}
		mainConfig.DatabaseURL = wl_db.URL(ctext)
		jsonBytes, err := json.Marshal(mainConfig)
		if err != nil {
			return err
		}
		err = os.WriteFile(MainConfigFile, pretty.Pretty(jsonBytes), 0666)
		if err != nil {
			return err
		}
	} else {
		return errors.New("invalid database url")
	}

	loginAudit = &LoginAudit{
		AccountMap: make(map[string]map[int64]int),
		IPMap:      make(map[string]map[int64]int),
	}

	mainConfig.HttpsCrtFile = strings.ReplaceAll(mainConfig.HttpsCrtFile, "{BasePath}", basepath)
	mainConfig.HttpsKeyFile = strings.ReplaceAll(mainConfig.HttpsKeyFile, "{BasePath}", basepath)

	keyFile := strings.ReplaceAll(mainConfig.RSAKeyFile, "{BasePath}", basepath)
	pubFile := strings.ReplaceAll(mainConfig.RSAPubFile, "{BasePath}", basepath)
	privateKey, err = LoadPrivateKey(keyFile)
	if err != nil {
		return err
	}
	publicKey, err = LoadPublicKey(pubFile)
	if err != nil {
		return err
	}

	codeMap = &CodeMap{
		Map: make(map[string]*Code),
	}

	return nil
}

func LoadPrivateKey(filePath string) (*rsa.PrivateKey, error) {
	contentBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("%v does not exist", filePath)
	}

	block, _ := pem.Decode(contentBytes)
	if block == nil {
		return nil, errors.New("invalid key")
	}

	var parsedKey any
	if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, err
		}
	}

	if pkey, ok := parsedKey.(*rsa.PrivateKey); ok {
		return pkey, nil
	}
	return nil, errors.New("invalid key")
}

func LoadPublicKey(filePath string) (*rsa.PublicKey, error) {
	contentBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("%v does not exist", filePath)
	}

	block, _ := pem.Decode(contentBytes)
	if block == nil {
		return nil, errors.New("invalid key")
	}

	var parsedKey any
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			if parsedKey, err = x509.ParsePKCS1PublicKey(block.Bytes); err != nil {
				return nil, err
			}
		}
	}

	if pkey, ok := parsedKey.(*rsa.PublicKey); ok {
		return pkey, nil
	}
	return nil, errors.New("invalid key")
}
