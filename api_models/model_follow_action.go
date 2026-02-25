package api_models

type FollowAction struct {

	// Username to follow (optional, either this or \"unfollow\")
	Follow string `json:"follow,omitempty"`

	// Username to unfollow (optional, either this or \"follow\")
	Unfollow string `json:"unfollow,omitempty"`
}

// AssertFollowActionRequired checks if the required fields are not zero-ed
func AssertFollowActionRequired(obj FollowAction) error {
	return nil
}

// AssertFollowActionConstraints checks if the values respects the defined constraints
func AssertFollowActionConstraints(obj FollowAction) error {
	return nil
}
