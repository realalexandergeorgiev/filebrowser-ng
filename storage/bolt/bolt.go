package bolt

import (
	boltapi "go.etcd.io/bbolt"

	"github.com/realalexandergeorgiev/filebrowser-ng/auth"
	"github.com/realalexandergeorgiev/filebrowser-ng/sessions"
	"github.com/realalexandergeorgiev/filebrowser-ng/settings"
	"github.com/realalexandergeorgiev/filebrowser-ng/share"
	"github.com/realalexandergeorgiev/filebrowser-ng/storage"
	"github.com/realalexandergeorgiev/filebrowser-ng/users"
)

// NewStorage creates a storage.Storage based on Bolt DB.
func NewStorage(db *boltapi.DB) (*storage.Storage, error) {
	userStore := users.NewStorage(usersBackend{db: db})
	shareStore := share.NewStorage(shareBackend{db: db})
	settingsStore := settings.NewStorage(settingsBackend{db: db})
	authStore := auth.NewStorage(authBackend{db: db}, userStore)
	sessionStore := sessions.NewStorage(sessionBackend{db: db})

	err := kvPut(db, "version", 2)
	if err != nil {
		return nil, err
	}

	return &storage.Storage{
		Auth:     authStore,
		Users:    userStore,
		Share:    shareStore,
		Settings: settingsStore,
		Sessions: sessionStore,
	}, nil
}
