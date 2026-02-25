package config

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	Host                        string
	Port                        string
	Issuer                      string
	EnableOrganizationAPI       bool
	DevClientID                 string
	DevClientRedirectURI        string
	ConfidentialClientID        string
	ConfidentialSecret          string
	ConfidentialRedirect        string
	EnablePrivateJWT            bool
	PrivateJWTClientID          string
	PrivateJWTRedirectURI       string
	PrivateJWTPublicKeyPEM      string
	PrivateJWTPublicKeyPath     string
	ClientRegistryPath          string
	AdminAuthMode               string
	AdminJWTSecret              string
	AdminJWTIssuer              string
	AdminJWTAudience            string
	EnablePrivateJWTKeyRotation bool
	PrivateJWTKeyRotationToken  string
	EnableSigningKeyRotationAPI bool
	SigningKeyRotationToken     string

	OrganizationAuthMode        string
	OrganizationAuthStaticToken string
	OrganizationJWTSecret       string
	OrganizationJWTIssuer       string
	OrganizationJWTAudience     string

	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string
}

func Load() *Config {
	return &Config{
		Host:                        getEnv("HOST", "0.0.0.0"),
		Port:                        getEnv("PORT", "8080"),
		Issuer:                      getEnv("ISSUER", "http://localhost:8080"),
		EnableOrganizationAPI:       getEnvBool("ENABLE_ORGANIZATION_API", false),
		DevClientID:                 getEnv("OIDC_DEV_CLIENT_ID", "local-dev-client"),
		DevClientRedirectURI:        getEnv("OIDC_DEV_REDIRECT_URI", "http://localhost:3000/callback"),
		ConfidentialClientID:        getEnv("OIDC_CONFIDENTIAL_CLIENT_ID", "local-confidential-client"),
		ConfidentialSecret:          getEnv("OIDC_CONFIDENTIAL_CLIENT_SECRET", "local-confidential-secret"),
		ConfidentialRedirect:        getEnv("OIDC_CONFIDENTIAL_REDIRECT_URI", "http://localhost:3000/callback"),
		EnablePrivateJWT:            getEnvBool("OIDC_PRIVATE_JWT_ENABLED", true),
		PrivateJWTClientID:          getEnv("OIDC_PRIVATE_JWT_CLIENT_ID", "local-private-jwt-client"),
		PrivateJWTRedirectURI:       getEnv("OIDC_PRIVATE_JWT_REDIRECT_URI", "http://localhost:3000/callback"),
		PrivateJWTPublicKeyPEM:      getEnv("OIDC_PRIVATE_JWT_CLIENT_PUBLIC_KEY_PEM", ""),
		PrivateJWTPublicKeyPath:     getEnv("OIDC_PRIVATE_JWT_CLIENT_PUBLIC_KEY_PATH", "config/keys/local/private_jwt_client_public.pem"),
		ClientRegistryPath:          getEnv("OIDC_CLIENT_REGISTRY_PATH", ""),
		AdminAuthMode:               strings.TrimSpace(strings.ToLower(getEnv("OIDC_ADMIN_AUTH_MODE", "static"))),
		AdminJWTSecret:              getEnv("OIDC_ADMIN_JWT_HS256_SECRET", ""),
		AdminJWTIssuer:              getEnv("OIDC_ADMIN_JWT_ISS", ""),
		AdminJWTAudience:            getEnv("OIDC_ADMIN_JWT_AUD", "oidc-admin"),
		EnablePrivateJWTKeyRotation: getEnvBool("OIDC_ENABLE_PRIVATE_JWT_KEY_ROTATION_API", false),
		PrivateJWTKeyRotationToken:  getEnv("OIDC_PRIVATE_JWT_KEY_ROTATION_TOKEN", "dev-private-jwt-key-rotation-token"),
		EnableSigningKeyRotationAPI: getEnvBool("OIDC_ENABLE_SIGNING_KEY_ROTATION_API", false),
		SigningKeyRotationToken:     getEnv("OIDC_SIGNING_KEY_ROTATION_TOKEN", "dev-signing-key-rotation-token"),
		OrganizationAuthMode:        strings.TrimSpace(strings.ToLower(getEnv("ORGANIZATION_AUTH_MODE", "static"))),
		OrganizationAuthStaticToken: getEnv("ORGANIZATION_AUTH_STATIC_TOKEN", "dev-organization-admin-token"),
		OrganizationJWTSecret:       getEnv("ORGANIZATION_JWT_HS256_SECRET", ""),
		OrganizationJWTIssuer:       getEnv("ORGANIZATION_JWT_ISS", ""),
		OrganizationJWTAudience:     getEnv("ORGANIZATION_JWT_AUD", "organization-api"),

		DBHost:     getEnv("DB_HOST", "localhost"),
		DBPort:     getEnv("DB_PORT", "3306"),
		DBUser:     getEnv("DB_USER", "root"),
		DBPassword: getEnv("DB_PASSWORD", ""),
		DBName:     getEnv("DB_NAME", "oauth21_idp"),
	}
}

func (c *Config) Addr() string {
	return fmt.Sprintf("%s:%s", c.Host, c.Port)
}

func (c *Config) DSN() string {
	return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true",
		c.DBUser, c.DBPassword, c.DBHost, c.DBPort, c.DBName,
	)
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if v == "" {
		return fallback
	}
	switch v {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}
