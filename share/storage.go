package share

import (
	"time"

	fberrors "github.com/realalexandergeorgiev/filebrowser-ng/errors"
)

// StorageBackend is the interface to implement for a share storage.
type StorageBackend interface {
	All() ([]*Link, error)
	FindByUserID(id uint) ([]*Link, error)
	GetByHash(hash string) (*Link, error)
	GetPermanent(path string, id uint) (*Link, error)
	Gets(path string, id uint) ([]*Link, error)
	Save(s *Link) error
	Delete(hash string) error
	DeleteWithPathPrefix(path string, userID uint) error
}

// Storage is a storage.
type Storage struct {
	back StorageBackend
}

// NewStorage creates a share links storage from a backend.
func NewStorage(back StorageBackend) *Storage {
	return &Storage{back: back}
}

// sweepExpired deletes expired links and returns only the live ones. It must
// not mutate the slice it ranges over (append-in-range skips consecutive
// expiries), so it builds a fresh result instead.
func (s *Storage) sweepExpired(links []*Link) ([]*Link, error) {
	now := time.Now().Unix()
	kept := links[:0]
	for _, link := range links {
		if link.Expire != 0 && link.Expire <= now {
			if err := s.Delete(link.Hash); err != nil {
				return nil, err
			}
			continue
		}
		kept = append(kept, link)
	}
	// Clear the tail so dropped entries cannot linger via the backing array.
	for i := len(kept); i < len(links); i++ {
		links[i] = nil
	}
	return kept, nil
}

// All wraps a StorageBackend.All.
func (s *Storage) All() ([]*Link, error) {
	links, err := s.back.All()

	if err != nil {
		return nil, err
	}

	return s.sweepExpired(links)
}

// FindByUserID wraps a StorageBackend.FindByUserID.
func (s *Storage) FindByUserID(id uint) ([]*Link, error) {
	links, err := s.back.FindByUserID(id)

	if err != nil {
		return nil, err
	}

	return s.sweepExpired(links)
}

// GetByHash wraps a StorageBackend.GetByHash.
func (s *Storage) GetByHash(hash string) (*Link, error) {
	link, err := s.back.GetByHash(hash)
	if err != nil {
		return nil, err
	}

	if link.Expire != 0 && link.Expire <= time.Now().Unix() {
		if err := s.Delete(link.Hash); err != nil {
			return nil, err
		}
		return nil, fberrors.ErrNotExist
	}

	return link, nil
}

// GetPermanent wraps a StorageBackend.GetPermanent
func (s *Storage) GetPermanent(path string, id uint) (*Link, error) {
	return s.back.GetPermanent(path, id)
}

// Gets wraps a StorageBackend.Gets
func (s *Storage) Gets(path string, id uint) ([]*Link, error) {
	links, err := s.back.Gets(path, id)

	if err != nil {
		return nil, err
	}

	return s.sweepExpired(links)
}

// Save wraps a StorageBackend.Save
func (s *Storage) Save(l *Link) error {
	return s.back.Save(l)
}

// Delete wraps a StorageBackend.Delete
func (s *Storage) Delete(hash string) error {
	return s.back.Delete(hash)
}

func (s *Storage) DeleteWithPathPrefix(path string, userID uint) error {
	return s.back.DeleteWithPathPrefix(path, userID)
}
