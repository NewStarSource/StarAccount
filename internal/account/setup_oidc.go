package account

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
)

func InitOIDC() error {
	config, _, err := LoadConfig(".local/development.json")
	if err != nil {
		return err
	}
	config.AtlasOrigin = "http://127.0.0.1:4200"
	config.SigningKeyFile = ".local/oidc-signing.pem"
	config.OIDCSecretFile = ".local/oidc-client.secret"
	if _, err = os.Stat(config.SigningKeyFile); os.IsNotExist(err) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		encoded, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		file, err := os.OpenFile(config.SigningKeyFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		writeErr := pem.Encode(file, &pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	} else if err != nil {
		return err
	}
	if _, err = os.Stat(config.OIDCSecretFile); os.IsNotExist(err) {
		file, err := os.OpenFile(config.OIDCSecretFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, writeErr := file.WriteString(randomToken())
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	} else if err != nil {
		return err
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(".local/development.json", data, 0600)
}
