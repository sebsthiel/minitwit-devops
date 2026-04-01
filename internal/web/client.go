package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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

func (c *APIClient) PostMessage(username string, text string) error {

	body := api_models.PostMessage{
		Content: text,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(
		"POST",
		c.BaseURL+"/api/msgs/"+username,
		bytes.NewBuffer(jsonBody),
	)

	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	authValue := os.Getenv("SIMULATOR_AUTH")
	if authValue == "" {
		authValue = "Basic c2ltdWxhdG9yOnN1cGVyX3NhZmUh"
	}

	req.Header.Set("Authorization", authValue)

	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("api returned %d", resp.StatusCode)
	}

	return nil
}

func (c *APIClient) FollowUser(
	username string,
	target string,
) error {

	body := api_models.FollowAction{
		Follow: target,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(
		"POST",
		c.BaseURL+"/api/fllws/"+username,
		bytes.NewBuffer(jsonBody),
	)

	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	authValue := os.Getenv("SIMULATOR_AUTH")

	if authValue == "" {
		authValue = "Basic c2ltdWxhdG9yOnN1cGVyX3NhZmUh"
	}

	req.Header.Set("Authorization", authValue)

	resp, err := c.Client.Do(req)

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("api error %d", resp.StatusCode)
	}

	return nil
}

func (c *APIClient) UnfollowUser(
	username string,
	target string,
) error {

	body := api_models.FollowAction{
		Unfollow: target,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(
		"POST",
		c.BaseURL+"/api/fllws/"+username,
		bytes.NewBuffer(jsonBody),
	)

	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	authValue := os.Getenv("SIMULATOR_AUTH")

	if authValue == "" {
		authValue = "Basic c2ltdWxhdG9yOnN1cGVyX3NhZmUh"
	}

	req.Header.Set("Authorization", authValue)

	resp, err := c.Client.Do(req)

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("api error %d", resp.StatusCode)
	}

	return nil
}

func (c *APIClient) RegisterUser(
	username string,
	email string,
	password string,
) error {

	body := api_models.RegisterRequest{
		Username: username,
		Email:    email,
		Pwd:      password,
	}

	jsonBody, err := json.Marshal(body)

	if err != nil {
		return err
	}

	req, err := http.NewRequest(
		"POST",
		c.BaseURL+"/api/register",
		bytes.NewBuffer(jsonBody),
	)

	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	authValue := os.Getenv("SIMULATOR_AUTH")

	if authValue == "" {
		authValue = "Basic c2ltdWxhdG9yOnN1cGVyX3NhZmUh"
	}

	req.Header.Set("Authorization", authValue)

	resp, err := c.Client.Do(req)

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {

		body, _ := io.ReadAll(resp.Body)

		return fmt.Errorf(
			"register failed: %s",
			string(body),
		)
	}

	return nil
}

func (c *APIClient) GetUserMessages(
	username string,
) ([]api_models.Message, error) {

	req, err := http.NewRequest(
		"GET",
		c.BaseURL+"/api/msgs/"+username,
		nil,
	)

	if err != nil {
		return nil, err
	}

	authValue := os.Getenv("SIMULATOR_AUTH")

	if authValue == "" {
		authValue = "Basic c2ltdWxhdG9yOnN1cGVyX3NhZmUh"
	}

	req.Header.Set(
		"Authorization",
		authValue,
	)

	resp, err := c.Client.Do(req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {

		return nil,
			fmt.Errorf(
				"api returned %d",
				resp.StatusCode,
			)
	}

	var messages []api_models.Message

	err = json.NewDecoder(
		resp.Body,
	).Decode(&messages)

	if err != nil {
		return nil, err
	}

	return messages, nil
}

func (c *APIClient) Login(
	username string,
	password string,
) (map[string]any, error) {

	body := map[string]string{

		"username": username,

		"password": password,
	}

	jsonBody, _ := json.Marshal(body)

	req, err := http.NewRequest(

		"POST",

		c.BaseURL+"/api/login",

		bytes.NewBuffer(jsonBody),
	)

	if err != nil {
		return nil, err
	}

	req.Header.Set(
		"Content-Type",
		"application/json",
	)

	resp, err := c.Client.Do(req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {

		body, _ := io.ReadAll(resp.Body)

		return nil,
			fmt.Errorf(string(body))
	}

	var user map[string]any

	json.NewDecoder(resp.Body).Decode(&user)

	return user, nil
}

func (c *APIClient) GetFollows(username string) ([]string, error) {

	req, err := http.NewRequest(
		"GET",
		c.BaseURL+"/api/fllws/"+username,
		nil,
	)

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

	var data struct {
		Follows []string
	}

	json.NewDecoder(resp.Body).Decode(&data)

	return data.Follows, nil
}
