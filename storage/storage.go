package storage

import (
	"github.com/realalexandergeorgiev/filebrowser-ng/auth"
	"github.com/realalexandergeorgiev/filebrowser-ng/sessions"
	"github.com/realalexandergeorgiev/filebrowser-ng/settings"
	"github.com/realalexandergeorgiev/filebrowser-ng/share"
	"github.com/realalexandergeorgiev/filebrowser-ng/users"
)

// Storage is a storage powered by a Backend which makes the necessary
// verifications when fetching and saving data to ensure consistency.
type Storage struct {
	Users    users.Store
	Share    *share.Storage
	Auth     *auth.Storage
	Settings *settings.Storage
	// Sessions holds the server-side login sessions that back the access
	// tokens. A token whose session is unknown or expired is refused.
	Sessions *sessions.Storage
}
