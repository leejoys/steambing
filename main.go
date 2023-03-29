package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/yohcop/openid-go"
)

// Encrypt encrypts data with a random key and nonce using AES-GCM algorithm
func Encrypt(data []byte) (string, error) {
	// Create a cipher block with a random key
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	// Create a GCM mode with the cipher block
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	// Encrypt the data with the key and nonce
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	// Encode the key and ciphertext with base64
	return base64.StdEncoding.EncodeToString(append(key, ciphertext...)), nil
}

// Decrypt decrypts data with a key and nonce using AES-GCM algorithm
func Decrypt(data string) ([]byte, error) {
	// Decode the data with base64
	rawdata, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	// Extract the key and ciphertext from the raw data
	key := rawdata[:32]
	ciphertext := rawdata[32:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, err
	}
	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]
	// Decrypt the ciphertext with the key and nonce
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// newOpenIDWithDiscoveryCacheAndNonceStore creates an OpenID with a discovery cache and a nonce store
func newOpenIDWithDiscoveryCacheAndNonceStore(opEndpoint string, returnTo string, discoveryCache openid.DiscoveryCache, nonceStore openid.NonceStore) *openid.OpenID {
	op := &openid.OpenID{
		OpEndpoint:     opEndpoint,
		ReturnTo:       returnTo,
		Realm:          returnTo,
		Mode:           "checkid_setup",
		NS:             "http://specs.openid.net/auth/2.0",
		DiscoveryCache: discoveryCache,
		NonceStore:     nonceStore,
	}
	return op
}

// LoginHandler handles the /login endpoint
func LoginHandler(c echo.Context) error {
	// Create a nonceStore and a discoveryCache for verification
	nonceStore := openid.NewSimpleNonceStore()
	discoveryCache := &openid.SimpleDiscoveryCache{}
	// Create an openid provider for Steam with the nonceStore and discoveryCache
	opId := newOpenIDWithDiscoveryCacheAndNonceStore("http://steamcommunity.com/openid", "http://localhost:8080/return", discoveryCache, nonceStore)
	// Generate an authentication URL with the provider and a return URL
	authUrl := opId.AuthUrl()
	// Serialize the nonceStore and discoveryCache values as bytes using the provider's methods
	nonceStoreBytes, err := opId.MarshalBinary(nonceStore)
	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}
	discoveryCacheBytes, err := opId.MarshalBinary(discoveryCache)
	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}
	// Encrypt the nonceStore and discoveryCache values with AES-GCM algorithm
	nonceStoreEncrypted, err := Encrypt(nonceStoreBytes)
	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}
	discoveryCacheEncrypted, err := Encrypt(discoveryCacheBytes)
	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}
	// Set cookies with the encrypted values of nonceStore and discoveryCache
	c.SetCookie(&http.Cookie{
		Name:  "nonceStore",
		Value: nonceStoreEncrypted,
	})
	c.SetCookie(&http.Cookie{
		Name:  "discoveryCache",
		Value: discoveryCacheEncrypted,
	})
	// Redirect the user to the authentication URL
	return c.Redirect(http.StatusFound, authUrl)
}

// ReturnHandler handles the /return endpoint
func ReturnHandler(c echo.Context) error {
	// Get the encrypted values of nonceStore and discoveryCache from the cookies
	nonceStoreCookie, err := c.Cookie("nonceStore")
	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}
	discoveryCacheCookie, err := c.Cookie("discoveryCache")
	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}
	nonceStoreEncrypted := nonceStoreCookie.Value
	discoveryCacheEncrypted := discoveryCacheCookie.Value
	// Decrypt the nonceStore and discoveryCache values with AES-GCM algorithm
	nonceStoreBytes, err := Decrypt(nonceStoreEncrypted)
	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}
	discoveryCacheBytes, err := Decrypt(discoveryCacheEncrypted)
	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}
	// Deserialize the nonceStore and discoveryCache values from bytes using the provider's methods
	var nonceStore openid.NonceStore
	var discoveryCache openid.DiscoveryCache
	opId := newOpenIDWithDiscoveryCacheAndNonceStore("http://steamcommunity.com/openid", "http://localhost:8080/return", discoveryCache, nonceStore)
	err = opId.UnmarshalBinary(&nonceStore, nonceStoreBytes)
	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}
	err = opId.UnmarshalBinary(&discoveryCache, discoveryCacheBytes)
	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}
	// Verify the openid response using the nonceStore and discoveryCache
	id, err := opId.Verify(
		c.Request().URL.String(),
		discoveryCache,
		nonceStore)
	if err != nil {
		// Handle error
		return c.String(http.StatusInternalServerError, err.Error())
	}
	// The id is the user's Steam ID
	return c.String(http.StatusOK, "Your Steam ID is "+id+"\n")
}
