//go:build unit
// +build unit

package mcpgrafana

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestForwardRequestHeadersFromEnv(t *testing.T) {
	t.Run("empty env returns nil", func(t *testing.T) {
		t.Setenv("GRAFANA_FORWARD_REQUEST_HEADERS", "")
		headers := forwardRequestHeadersFromEnv()
		assert.Nil(t, headers)
	})

	t.Run("single header", func(t *testing.T) {
		t.Setenv("GRAFANA_FORWARD_REQUEST_HEADERS", "Authorization")
		headers := forwardRequestHeadersFromEnv()
		assert.Equal(t, []string{"Authorization"}, headers)
	})

	t.Run("multiple headers comma-separated", func(t *testing.T) {
		t.Setenv("GRAFANA_FORWARD_REQUEST_HEADERS", "Authorization,X-Grafana-User-Email")
		headers := forwardRequestHeadersFromEnv()
		assert.Equal(t, []string{"Authorization", "X-Grafana-User-Email"}, headers)
	})

	t.Run("headers with whitespace", func(t *testing.T) {
		t.Setenv("GRAFANA_FORWARD_REQUEST_HEADERS", "Authorization , X-Grafana-User-Email , X-Custom")
		headers := forwardRequestHeadersFromEnv()
		assert.Equal(t, []string{"Authorization", "X-Grafana-User-Email", "X-Custom"}, headers)
	})

	t.Run("wildcard forwards all", func(t *testing.T) {
		t.Setenv("GRAFANA_FORWARD_REQUEST_HEADERS", "*")
		headers := forwardRequestHeadersFromEnv()
		assert.Equal(t, []string{"*"}, headers)
	})
}

func TestExtractForwardedHeaders(t *testing.T) {
	t.Run("empty allowed headers returns nil", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("Authorization", "Bearer token123")
		headers := extractForwardedHeaders(req, nil)
		assert.Nil(t, headers)
	})

	t.Run("extracts single whitelisted header", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("Authorization", "Bearer token123")
		req.Header.Set("X-Other", "should-not-be-forwarded")
		headers := extractForwardedHeaders(req, []string{"Authorization"})
		assert.Equal(t, map[string]string{"Authorization": "Bearer token123"}, headers)
	})

	t.Run("extracts multiple whitelisted headers", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("Authorization", "Bearer token123")
		req.Header.Set("X-Grafana-User-Email", "user@example.com")
		req.Header.Set("X-Other", "should-not-be-forwarded")
		headers := extractForwardedHeaders(req, []string{"Authorization", "X-Grafana-User-Email"})
		assert.Equal(t, map[string]string{
			"Authorization":        "Bearer token123",
			"X-Grafana-User-Email": "user@example.com",
		}, headers)
	})

	t.Run("ignores non-whitelisted headers", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("Authorization", "Bearer token123")
		req.Header.Set("X-Other", "should-not-be-forwarded")
		req.Header.Set("X-Another", "also-should-not-be-forwarded")
		headers := extractForwardedHeaders(req, []string{"Authorization"})
		assert.Equal(t, map[string]string{"Authorization": "Bearer token123"}, headers)
		assert.NotContains(t, headers, "X-Other")
		assert.NotContains(t, headers, "X-Another")
	})

	t.Run("wildcard forwards all headers", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("Authorization", "Bearer token123")
		req.Header.Set("X-Grafana-User-Email", "user@example.com")
		req.Header.Set("X-Custom", "custom-value")
		req.Header.Set("User-Agent", "test-agent")
		headers := extractForwardedHeaders(req, []string{"*"})
		assert.Contains(t, headers, "Authorization")
		assert.Contains(t, headers, "X-Grafana-User-Email")
		assert.Contains(t, headers, "X-Custom")
		assert.Contains(t, headers, "User-Agent")
		assert.Equal(t, "Bearer token123", headers["Authorization"])
		assert.Equal(t, "user@example.com", headers["X-Grafana-User-Email"])
	})

	t.Run("empty header value is not forwarded", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("Authorization", "Bearer token123")
		// Don't set X-Grafana-User-Email, so it will be empty
		headers := extractForwardedHeaders(req, []string{"Authorization", "X-Grafana-User-Email"})
		assert.Equal(t, map[string]string{"Authorization": "Bearer token123"}, headers)
		assert.NotContains(t, headers, "X-Grafana-User-Email")
	})
}

func TestExtractGrafanaInfoWithForwardedHeaders(t *testing.T) {
	t.Run("forwarded headers merged into ExtraHeaders", func(t *testing.T) {
		t.Setenv("GRAFANA_FORWARD_REQUEST_HEADERS", "Authorization,X-Grafana-User-Email")
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("Authorization", "Bearer token123")
		req.Header.Set("X-Grafana-User-Email", "user@example.com")
		ctx := ExtractGrafanaInfoFromHeaders(context.Background(), req)
		config := GrafanaConfigFromContext(ctx)
		assert.Equal(t, "Bearer token123", config.ExtraHeaders["Authorization"])
		assert.Equal(t, "user@example.com", config.ExtraHeaders["X-Grafana-User-Email"])
	})

	t.Run("forwarded headers take precedence over env headers", func(t *testing.T) {
		t.Setenv("GRAFANA_EXTRA_HEADERS", `{"Authorization": "env-token", "X-Static": "static-value"}`)
		t.Setenv("GRAFANA_FORWARD_REQUEST_HEADERS", "Authorization")
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("Authorization", "forwarded-token")
		ctx := ExtractGrafanaInfoFromHeaders(context.Background(), req)
		config := GrafanaConfigFromContext(ctx)
		// Forwarded header should override env header
		assert.Equal(t, "forwarded-token", config.ExtraHeaders["Authorization"])
		// Env-only header should still be present
		assert.Equal(t, "static-value", config.ExtraHeaders["X-Static"])
	})

	t.Run("env headers and forwarded headers both present", func(t *testing.T) {
		t.Setenv("GRAFANA_EXTRA_HEADERS", `{"X-Static": "static-value"}`)
		t.Setenv("GRAFANA_FORWARD_REQUEST_HEADERS", "Authorization")
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("Authorization", "forwarded-token")
		ctx := ExtractGrafanaInfoFromHeaders(context.Background(), req)
		config := GrafanaConfigFromContext(ctx)
		assert.Equal(t, "forwarded-token", config.ExtraHeaders["Authorization"])
		assert.Equal(t, "static-value", config.ExtraHeaders["X-Static"])
	})

	t.Run("no forwarded headers when env var not set", func(t *testing.T) {
		t.Setenv("GRAFANA_FORWARD_REQUEST_HEADERS", "")
		t.Setenv("GRAFANA_EXTRA_HEADERS", `{"X-Static": "static-value"}`)
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("Authorization", "should-not-be-forwarded")
		ctx := ExtractGrafanaInfoFromHeaders(context.Background(), req)
		config := GrafanaConfigFromContext(ctx)
		assert.Equal(t, "static-value", config.ExtraHeaders["X-Static"])
		assert.NotContains(t, config.ExtraHeaders, "Authorization")
	})

	t.Run("wildcard forwards all headers", func(t *testing.T) {
		t.Setenv("GRAFANA_FORWARD_REQUEST_HEADERS", "*")
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("Authorization", "Bearer token123")
		req.Header.Set("X-Grafana-User-Email", "user@example.com")
		req.Header.Set("X-Custom", "custom-value")
		ctx := ExtractGrafanaInfoFromHeaders(context.Background(), req)
		config := GrafanaConfigFromContext(ctx)
		assert.Contains(t, config.ExtraHeaders, "Authorization")
		assert.Contains(t, config.ExtraHeaders, "X-Grafana-User-Email")
		assert.Contains(t, config.ExtraHeaders, "X-Custom")
	})
}
