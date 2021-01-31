package util

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"io/ioutil"
	"net/http"
	"time"
)

var privateKey *rsa.PrivateKey

func SetRsaPrivateKey(pemFile string) error {
	bytes, err := ioutil.ReadFile(pemFile)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(bytes)
	if block == nil {
		return errors.New("invalid private key data")
	}

	var key *rsa.PrivateKey
	if block.Type == "RSA PRIVATE KEY" {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
	} else if block.Type == "PRIVATE KEY" {
		keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		var ok bool
		key, ok = keyInterface.(*rsa.PrivateKey)
		if !ok {
			return errors.New("not RSA private key")
		}
	} else {
		return fmt.Errorf("invalid private key type : %s", block.Type)
	}

	key.Precompute()

	if err := key.Validate(); err != nil {
		return err
	}

	privateKey = key
	return nil
}

func GetToken(claims map[string]interface{}) ([]byte, error) {
	var err error

	t := jwt.New()

	_ = t.Set(jwt.IssuerKey, "test@example.com")
	_ = t.Set(jwt.SubjectKey, "test@example.com")
	_ = t.Set(jwt.ExpirationKey, time.Now().Add(time.Hour*1).Unix())
	_ = t.Set(jwt.IssuedAtKey, time.Now().Unix())

	for k, v := range claims {
		err = t.Set(k, v)
		if err != nil {
			return nil, err
		}
	}

	realKey, err := jwk.New(privateKey)
	if err != nil {
		return nil, err
	}
	_ = realKey.Set(jwk.KeyIDKey, `example`)

	signed, err := jwt.Sign(t, jwa.RS256, realKey)
	if err != nil {
		return nil, err
	}

	return signed, nil
}
func AuthCheck(c *gin.Context) {
	pubKey, err := jwk.New(privateKey.PublicKey)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	_ = pubKey.Set(jwk.KeyIDKey, "example")

	keySet := jwk.NewSet()
	keySet.Add(pubKey)

	token, err := jwt.Parse([]byte(c.GetHeader("Authorization")[7:]), jwt.WithKeySet(keySet))
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	c.Set("claims", token.PrivateClaims())
	c.Next()
	return
}
