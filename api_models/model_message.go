package api_models

type Message struct {

	// Text content of the message
	Content string `json:"content,omitempty"`

	// Publication date/time of the message
	PubDate string `json:"pub_date,omitempty"`

	// Username of the message author
	User string `json:"user,omitempty"`
}

// AssertMessageRequired checks if the required fields are not zero-ed
func AssertMessageRequired(obj Message) error {
	return nil
}

// AssertMessageConstraints checks if the values respects the defined constraints
func AssertMessageConstraints(obj Message) error {
	return nil
}
