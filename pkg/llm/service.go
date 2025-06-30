package llm

import (
	"context"
	"fmt"
	"log"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
)

// Service provides LLM capabilities using Bifrost
type Service struct {
	client *bifrost.Client
	logger *log.Logger
}

// NewService creates a new LLM service with Bifrost integration
func NewService(logger *log.Logger) (*Service, error) {
	account := NewBifrostAccount()

	// Initialize Bifrost client
	client, err := bifrost.Init(schemas.BifrostConfig{
		Account: account,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Bifrost client: %w", err)
	}

	return &Service{
		client: client,
		logger: logger,
	}, nil
}

// Close cleans up the LLM service
func (s *Service) Close() {
	if s.client != nil {
		s.client.Cleanup()
	}
}

// ChatRequest represents a chat completion request
type ChatRequest struct {
	Provider     schemas.ModelProvider `json:"provider"`
	Model        string                `json:"model"`
	Messages     []ChatMessage         `json:"messages"`
	SystemPrompt string                `json:"system_prompt,omitempty"`
	MaxTokens    int                   `json:"max_tokens,omitempty"`
	Temperature  float64               `json:"temperature,omitempty"`
}

// ChatMessage represents a single message in a chat
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatResponse represents the response from a chat completion
type ChatResponse struct {
	Content  string                `json:"content"`
	Provider schemas.ModelProvider `json:"provider"`
	Model    string                `json:"model"`
	Usage    *Usage                `json:"usage,omitempty"`
}

// Usage represents token usage information
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ChatCompletion performs a chat completion using the configured LLM provider
func (s *Service) ChatCompletion(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	// Convert our messages to Bifrost format
	var messages []schemas.Message

	// Add system message if provided
	if req.SystemPrompt != "" {
		messages = append(messages, schemas.Message{
			Role:    schemas.System,
			Content: schemas.Content{ContentStr: bifrost.Ptr(req.SystemPrompt)},
		})
	}

	// Add user messages
	for _, msg := range req.Messages {
		var role schemas.MessageRole
		switch msg.Role {
		case "user":
			role = schemas.User
		case "assistant":
			role = schemas.Assistant
		case "system":
			role = schemas.System
		default:
			role = schemas.User // Default to user
		}

		messages = append(messages, schemas.Message{
			Role:    role,
			Content: schemas.Content{ContentStr: bifrost.Ptr(msg.Content)},
		})
	}

	// Create Bifrost request
	bifrostReq := schemas.ChatCompletionRequest{
		Provider: req.Provider,
		Model:    req.Model,
		Messages: messages,
	}

	// Set optional parameters
	if req.MaxTokens > 0 {
		bifrostReq.MaxTokens = &req.MaxTokens
	}
	if req.Temperature > 0 {
		bifrostReq.Temperature = &req.Temperature
	}

	// Make the request
	response, err := s.client.ChatCompletionRequest(ctx, bifrostReq)
	if err != nil {
		return nil, fmt.Errorf("chat completion failed: %w", err)
	}

	// Extract response content
	if len(response.Choices) == 0 {
		return nil, fmt.Errorf("no response choices returned")
	}

	choice := response.Choices[0]
	if choice.Message.Content.ContentStr == nil {
		return nil, fmt.Errorf("no content in response")
	}

	// Create response
	chatResp := &ChatResponse{
		Content:  *choice.Message.Content.ContentStr,
		Provider: req.Provider,
		Model:    req.Model,
	}

	// Add usage information if available
	if response.Usage != nil {
		chatResp.Usage = &Usage{
			PromptTokens:     response.Usage.PromptTokens,
			CompletionTokens: response.Usage.CompletionTokens,
			TotalTokens:      response.Usage.TotalTokens,
		}
	}

	return chatResp, nil
}

// AnalyzeVulnerability uses LLM to analyze a vulnerability and provide insights
func (s *Service) AnalyzeVulnerability(ctx context.Context, vulnName, vulnDescription, target string) (*ChatResponse, error) {
	// Use a default provider and model if available
	providers, err := s.client.GetAccount().GetConfiguredProviders()
	if err != nil || len(providers) == 0 {
		return nil, fmt.Errorf("no LLM providers configured")
	}

	provider := providers[0] // Use first available provider
	var model string

	// Select appropriate model based on provider
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

	prompt := fmt.Sprintf(`Analyze this security vulnerability:

Vulnerability: %s
Description: %s
Target: %s

Please provide:
1. Risk assessment (High/Medium/Low)
2. Potential impact
3. Recommended remediation steps
4. Prevention strategies

Keep the response concise and actionable.`, vulnName, vulnDescription, target)

	req := ChatRequest{
		Provider: provider,
		Model:    model,
		Messages: []ChatMessage{
			{Role: "user", Content: prompt},
		},
		SystemPrompt: "You are a cybersecurity expert analyzing vulnerabilities. Provide clear, actionable security advice.",
		MaxTokens:    1000,
		Temperature:  0.1,
	}

	return s.ChatCompletion(ctx, req)
}

// GenerateRecommendations uses LLM to generate security recommendations based on scan results
func (s *Service) GenerateRecommendations(ctx context.Context, findings []string) (*ChatResponse, error) {
	if len(findings) == 0 {
		return nil, fmt.Errorf("no findings provided")
	}

	// Use a default provider and model if available
	providers, err := s.client.GetAccount().GetConfiguredProviders()
	if err != nil || len(providers) == 0 {
		return nil, fmt.Errorf("no LLM providers configured")
	}

	provider := providers[0] // Use first available provider
	var model string

	// Select appropriate model based on provider
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

	findingsList := ""
	for i, finding := range findings {
		findingsList += fmt.Sprintf("%d. %s\n", i+1, finding)
	}

	prompt := fmt.Sprintf(`Based on these security scan findings, provide prioritized recommendations:

%s

Please provide:
1. Priority ranking of issues
2. Specific remediation steps for each finding
3. Overall security posture assessment
4. Quick wins vs long-term improvements

Focus on actionable advice.`, findingsList)

	req := ChatRequest{
		Provider: provider,
		Model:    model,
		Messages: []ChatMessage{
			{Role: "user", Content: prompt},
		},
		SystemPrompt: "You are a cybersecurity consultant providing actionable security recommendations. Be specific and practical.",
		MaxTokens:    1500,
		Temperature:  0.2,
	}

	return s.ChatCompletion(ctx, req)
}

// GetAccount returns the underlying Bifrost account for provider access
func (s *Service) GetAccount() schemas.Account {
	return s.client.GetAccount()
}
