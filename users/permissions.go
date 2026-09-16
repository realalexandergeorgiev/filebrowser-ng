package users

// Permissions describe a user's permissions.
type Permissions struct {
	Admin bool `json:"admin"`
	// Execute is deprecated: command execution was removed, nothing
	// evaluates this flag anymore. Kept for API compatibility until the
	// frontend stops sending it.
	Execute  bool `json:"execute"`
	Create   bool `json:"create"`
	Rename   bool `json:"rename"`
	Modify   bool `json:"modify"`
	Delete   bool `json:"delete"`
	Share    bool `json:"share"`
	Download bool `json:"download"`
}
