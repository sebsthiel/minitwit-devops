package models

type Data struct {
	User         *User
	ProfileUser  *User
	Error        string
	FormUsername string
	Flashes      []string
	Messages     []map[string]any
	Endpoint     string
	Followed     bool
}

type User struct {
	User_id  int `gorm:"column:user_id;primaryKey;autoIncrement"`
	Username string
	Email    string
	Pw_hash  string `gorm:"column:pw_hash"`
}

type Message struct {
	Message_id int `gorm:"column:message_id;primaryKey;autoIncrement"`
	Author_id  int
	Text       string
	Pub_date   int
	Flagged    int
}

type Follower struct {
	Who_id  int
	Whom_id int
}