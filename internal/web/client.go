package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"devops/minitwit/api_models"
)

type APIClient struct {
	BaseURL string
	Client  *http.Client
}

func NewAPIClient() *APIClient {
	baseURL := os.Getenv("API_BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:5001"
	}

	return &APIClient{
		BaseURL: baseURL,
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *APIClient) GetPublicMessages() ([]api_models.Message, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/api/msgs", nil)
	if err != nil {
		return nil, err
	}

	authValue := os.Getenv("SIMULATOR_AUTH")
	if authValue == "" {
		authValue = "Basic c2ltdWxhdG9yOnN1cGVyX3NhZmUh"
	}
	req.Header.Set("Authorization", authValue)

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("api returned status %d", resp.StatusCode)
	}

	var messages []api_models.Message
	if err := json.NewDecoder(resp.Body).Decode(&messages); err != nil {
		return nil, err
	}

	return messages, nil
}