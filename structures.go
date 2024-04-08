package main

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
)

// App holds application-wide dependencies
type App struct {
	DB *sql.DB
}

type User struct {
	Username  string
	Role      string
	LastLogin string
	Uid       string
}

type APIToken struct {
	Token     string
	CreatedAt string
	Id        string
}

type BlindfoldKeyRequest struct {
	TenantURL         string `json:"tenantUrl" binding:"required"`
	TenantToken       string `json:"tenantToken" binding:"required"`
	PrivateKey        string `json:"privateKey" binding:"required"`
	SecretsPolicyName string `json:"secretsPolicyName"` // Optional
}

// Structs for parsing JSON
type SecretPolicyInput struct {
	Data struct {
		Tenant     string `json:"tenant"`
		PolicyID   string `json:"policy_id"`
		PolicyInfo struct {
			Rules []interface{} `json:"rules"`
		} `json:"policy_info"`
	} `json:"data"`
}

// Structs for generating YAML
type SecretPolicyOutput struct {
	Data struct {
		Tenant     string `yaml:"tenant"`
		PolicyID   string `yaml:"policyId"`
		PolicyInfo struct {
			Rules []interface{} `yaml:"rules"`
		} `yaml:"policyInfo"`
	} `yaml:"data"`
}

// JSONInput matches the structure of the JSON input
type PublicKeyInput struct {
	Data struct {
		Tenant               string `json:"tenant"`
		KeyVersion           int    `json:"key_version"`
		ModulusBase64        string `json:"modulus_base64"`
		PublicExponentBase64 string `json:"public_exponent_base64"`
	} `json:"data"`
}

// YAMLOutput matches the structure of the desired YAML output
type PublicKeyOutput struct {
	Data struct {
		Tenant               string `yaml:"tenant"`
		KeyVersion           int    `yaml:"keyVersion"`
		ModulusBase64        string `yaml:"modulusBase64"`
		PublicExponentBase64 string `yaml:"publicExponentBase64"`
	} `yaml:"data"`
}

type BlindfoldCertificate struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Spec struct {
		CertificateURL string `json:"certificate_url"`
		PrivateKey     struct {
			BlindfoldSecretInfo struct {
				Location string `json:"location"`
			} `json:"blindfold_secret_info"`
		} `json:"private_key"`
	} `json:"spec"`
}
