package api_models

type ErrorResponse struct {

	// HTTP error code
	Status int32 `json:"status,omitempty"`

	// Error message
	ErrorMsg string `json:"error_msg,omitempty"`
}

// AssertErrorResponseRequired checks if the required fields are not zero-ed
func AssertErrorResponseRequired(obj ErrorResponse) error {
	return nil
}

// AssertErrorResponseConstraints checks if the values respects the defined constraints
func AssertErrorResponseConstraints(obj ErrorResponse) error {
	return nil
}
