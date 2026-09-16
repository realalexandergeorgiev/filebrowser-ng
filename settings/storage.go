package settings

import (
	fberrors "github.com/realalexandergeorgiev/filebrowser-ng/errors"
	"github.com/realalexandergeorgiev/filebrowser-ng/rules"
	"github.com/realalexandergeorgiev/filebrowser-ng/users"
)

// StorageBackend is a settings storage backend.
type StorageBackend interface {
	Get() (*Settings, error)
	Save(*Settings) error
	GetServer() (*Server, error)
	SaveServer(*Server) error
}

// Storage is a settings storage.
type Storage struct {
	back StorageBackend
}

// NewStorage creates a settings storage from a backend.
func NewStorage(back StorageBackend) *Storage {
	return &Storage{back: back}
}

// Get returns the settings for the current instance.
func (s *Storage) Get() (*Settings, error) {
	set, err := s.back.Get()
	if err != nil {
		return nil, err
	}

	if set.UserHomeBasePath == "" {
		set.UserHomeBasePath = DefaultUsersHomeBasePath
	}

	if set.LogoutPage == "" {
		set.LogoutPage = DefaultLogoutPage
	}

	if set.MinimumPasswordLength == 0 {
		set.MinimumPasswordLength = DefaultMinimumPasswordLength
	}

	if set.Tus == (Tus{}) {
		set.Tus = Tus{
			ChunkSize:  DefaultTusChunkSize,
			RetryCount: DefaultTusRetryCount,
		}
	}

	if set.FileMode == 0 {
		set.FileMode = DefaultFileMode
	}

	if set.DirMode == 0 {
		set.DirMode = DefaultDirMode
	}

	return set, nil
}

// Save saves the settings for the current instance.
func (s *Storage) Save(set *Settings) error {
	if len(set.Key) == 0 {
		return fberrors.ErrEmptyKey
	}

	if set.Defaults.Locale == "" {
		set.Defaults.Locale = "en"
	}

	if set.Defaults.Commands == nil {
		set.Defaults.Commands = []string{}
	}

	if set.Defaults.ViewMode == "" {
		set.Defaults.ViewMode = users.MosaicViewMode
	}

	if set.Rules == nil {
		set.Rules = []rules.Rule{}
	}

	err := s.back.Save(set)
	if err != nil {
		return err
	}

	return nil
}

// GetServer wraps StorageBackend.GetServer.
func (s *Storage) GetServer() (*Server, error) {
	return s.back.GetServer()
}

// SaveServer wraps StorageBackend.SaveServer and adds some verification.
func (s *Storage) SaveServer(ser *Server) error {
	ser.Clean()
	return s.back.SaveServer(ser)
}
