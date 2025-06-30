package llm

import (
	"fmt"
	"os"

	"github.com/maximhq/bifrost/core/schemas"
)

// BifrostAccount implements the Account interface for Bifrost
type BifrostAccount struct{}

// NewBifrostAccount creates a new Bifrost account implementation
func NewBifrostAccount() *BifrostAccount {
	return &BifrostAccount{}
}

// GetConfiguredProviders returns the list of configured LLM providers
func (a *BifrostAccount) GetConfiguredProviders() ([]schemas.ModelProvider, error) {
	var providers []schemas.ModelProvider

	// Check for OpenAI API key
	if os.Getenv("OPENAI_API_KEY") != "" {
		providers = append(providers, schemas.OpenAI)
	}

	// Check for Anthropic API key
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		providers = append(providers, schemas.Anthropic)
	}

	// Check for Google API key
	if os.Getenv("GOOGLE_API_KEY") != "" {
		providers = append(providers, schemas.Google)
	}

	// Check for Mistral API key
	if os.Getenv("MISTRAL_API_KEY") != "" {
		providers = append(providers, schemas.Mistral)
	}

	if len(providers) == 0 {
		return nil, fmt.Errorf("no LLM provider API keys found in environment variables")
	}

	return providers, nil
}

// GetKeysForProvider returns the API keys for a specific provider
func (a *BifrostAccount) GetKeysForProvider(provider schemas.ModelProvider) ([]schemas.Key, error) {
	switch provider {
	case schemas.OpenAI:
		key := os.Getenv("OPENAI_API_KEY")
		if key == "" {
			return nil, fmt.Errorf("OPENAI_API_KEY not found")
		}
		return []schemas.Key{{
			Value:  key,
			Models: []string{"gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"},
			Weight: 1.0,
		}}, nil

	case schemas.Anthropic:
		key := os.Getenv("ANTHROPIC_API_KEY")
		if key == "" {
			return nil, fmt.Errorf("ANTHROPIC_API_KEY not found")
		}
		return []schemas.Key{{
			Value:  key,
			Models: []string{"claude-3-5-sonnet-20241022", "claude-3-opus-20240229", "claude-3-sonnet-20240229", "claude-3-haiku-20240307"},
			Weight: 1.0,
		}}, nil

	case schemas.Google:
		key := os.Getenv("GOOGLE_API_KEY")
		if key == "" {
			return nil, fmt.Errorf("GOOGLE_API_KEY not found")
		}
		return []schemas.Key{{
			Value:  key,
			Models: []string{"gemini-1.5-pro", "gemini-1.5-flash"},
			Weight: 1.0,
		}}, nil

	case schemas.Mistral:
		key := os.Getenv("MISTRAL_API_KEY")
		if key == "" {
			return nil, fmt.Errorf("MISTRAL_API_KEY not found")
		}
		return []schemas.Key{{
			Value:  key,
			Models: []string{"mistral-large-latest", "mistral-medium-latest", "mistral-small-latest"},
			Weight: 1.0,
		}}, nil

	default:
		return nil, fmt.Errorf("provider %s not supported", provider)
	}
}

// GetConfigForProvider returns the configuration for a specific provider
func (a *BifrostAccount) GetConfigForProvider(provider schemas.ModelProvider) (*schemas.ProviderConfig, error) {
	// Return default configuration for all providers
	// This can be customized per provider if needed
	return &schemas.ProviderConfig{
		NetworkConfig:            schemas.DefaultNetworkConfig,
		ConcurrencyAndBufferSize: schemas.DefaultConcurrencyAndBufferSize,
	}, nil
}
