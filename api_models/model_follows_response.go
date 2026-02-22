package api_models

type FollowsResponse struct {

	// List of usernames the user is following
	Follows []string `json:"follows,omitempty"`
}

// AssertFollowsResponseRequired checks if the required fields are not zero-ed
func AssertFollowsResponseRequired(obj FollowsResponse) error {
	return nil
}

// AssertFollowsResponseConstraints checks if the values respects the defined constraints
func AssertFollowsResponseConstraints(obj FollowsResponse) error {
	return nil
}
