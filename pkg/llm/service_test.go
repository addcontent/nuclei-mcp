package llm

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

func TestNewService(t *testing.T) {
	// Test with no API keys - should fail gracefully
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)

	// Clear any existing API keys for this test
	originalKeys := map[string]string{
		"OPENAI_API_KEY":    os.Getenv("OPENAI_API_KEY"),
		"ANTHROPIC_API_KEY": os.Getenv("ANTHROPIC_API_KEY"),
		"GOOGLE_API_KEY":    os.Getenv("GOOGLE_API_KEY"),
		"MISTRAL_API_KEY":   os.Getenv("MISTRAL_API_KEY"),
	}

	// Clear all API keys
	for key := range originalKeys {
		os.Unsetenv(key)
	}

	// Restore original keys after test
	defer func() {
		for key, value := range originalKeys {
			if value != "" {
				os.Setenv(key, value)
			}
		}
	}()

	// This should fail because no API keys are set
	service, err := NewService(logger)
	if err == nil {
		t.Error("Expected error when no API keys are configured, but got nil")
		if service != nil {
			service.Close()
		}
		return
	}

	t.Logf("Correctly failed with error: %v", err)
}

func TestNewServiceWithAPIKey(t *testing.T) {
	// Skip if no API key is available
	if os.Getenv("OPENAI_API_KEY") == "" && os.Getenv("ANTHROPIC_API_KEY") == "" {
		t.Skip("Skipping test - no LLM API keys configured")
	}

	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)

	service, err := NewService(logger)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	if service.client == nil {
		t.Error("Service client is nil")
	}

	// Test that we can get configured providers
	providers, err := service.GetAccount().GetConfiguredProviders()
	if err != nil {
		t.Errorf("Failed to get configured providers: %v", err)
	}

	if len(providers) == 0 {
		t.Error("No providers configured")
	}

	t.Logf("Configured providers: %v", providers)
}

func TestChatCompletion(t *testing.T) {
	// Skip if no API key is available
	if os.Getenv("OPENAI_API_KEY") == "" && os.Getenv("ANTHROPIC_API_KEY") == "" {
		t.Skip("Skipping test - no LLM API keys configured")
	}

	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)

	service, err := NewService(logger)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	// Get the first available provider
	providers, err := service.GetAccount().GetConfiguredProviders()
	if err != nil || len(providers) == 0 {
		t.Fatalf("No providers available: %v", err)
	}

	provider := providers[0]
	var model string

	// Select model based on provider
	switch provider {
	case schemas.OpenAI:
		model = "gpt-4o-mini"
	case schemas.Anthropic:
		model = "claude-3-5-sonnet-20241022"
	case schemas.Google:
		model = "gemini-1.5-flash"
	case schemas.Mistral:
		model = "mistral-small-latest"
	default:
		model = "gpt-4o-mini"
	}

	req := ChatRequest{
		Provider: provider,
		Model:    model,
		Messages: []ChatMessage{
			{Role: "user", Content: "Hello! Please respond with exactly: 'Test successful'"},
		},
		MaxTokens:   100,
		Temperature: 0.1,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	response, err := service.ChatCompletion(ctx, req)
	if err != nil {
		t.Fatalf("Chat completion failed: %v", err)
	}

	if response.Content == "" {
		t.Error("Response content is empty")
	}

	if response.Provider != provider {
		t.Errorf("Expected provider %s, got %s", provider, response.Provider)
	}

	if response.Model != model {
		t.Errorf("Expected model %s, got %s", model, response.Model)
	}

	t.Logf("Chat completion successful. Response: %s", response.Content)
	if response.Usage != nil {
		t.Logf("Token usage - Total: %d, Prompt: %d, Completion: %d",
			response.Usage.TotalTokens, response.Usage.PromptTokens, response.Usage.CompletionTokens)
	}
}
