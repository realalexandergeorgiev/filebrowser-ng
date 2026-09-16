package bolt

import (
	"encoding/json"
	"errors"
	"strings"

	boltapi "go.etcd.io/bbolt"

	fberrors "github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/share"
)

// shareBucket matches the storm bucket name for share.Link, so rows written
// before the migration stay readable and rollbacks work. Storm's
// __storm_index_* sub-buckets are left alone: queries scan and filter
// instead, which is plenty at share-link scale and drops index maintenance.
const shareBucket = "Link"

type shareBackend struct {
	db *boltapi.DB
}

func (s shareBackend) all() ([]*share.Link, error) {
	var out []*share.Link
	err := s.db.View(func(tx *boltapi.Tx) error {
		b := tx.Bucket([]byte(shareBucket))
		if b == nil {
			return fberrors.ErrNotExist
		}
		return b.ForEach(func(k, v []byte) error {
			if v == nil {
				return nil // index sub-bucket, not a link
			}
			var l share.Link
			if err := json.Unmarshal(v, &l); err != nil {
				return err
			}
			out = append(out, &l)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fberrors.ErrNotExist
	}
	return out, nil
}

func (s shareBackend) All() ([]*share.Link, error) {
	return s.all()
}

func (s shareBackend) FindByUserID(id uint) ([]*share.Link, error) {
	links, err := s.all()
	if err != nil {
		return nil, err
	}
	var out []*share.Link
	for _, l := range links {
		if l.UserID == id {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		return nil, fberrors.ErrNotExist
	}
	return out, nil
}

func (s shareBackend) GetByHash(hash string) (*share.Link, error) {
	var v share.Link
	err := s.db.View(func(tx *boltapi.Tx) error {
		b := tx.Bucket([]byte(shareBucket))
		if b == nil {
			return fberrors.ErrNotExist
		}
		raw := b.Get([]byte(hash))
		if raw == nil {
			return fberrors.ErrNotExist
		}
		return json.Unmarshal(raw, &v)
	})
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (s shareBackend) GetPermanent(path string, id uint) (*share.Link, error) {
	links, err := s.all()
	if err != nil {
		return nil, err
	}
	for _, l := range links {
		if l.Path == path && l.Expire == 0 && l.UserID == id {
			return l, nil
		}
	}
	return nil, fberrors.ErrNotExist
}

func (s shareBackend) Gets(path string, id uint) ([]*share.Link, error) {
	links, err := s.all()
	if err != nil {
		return nil, err
	}
	var out []*share.Link
	for _, l := range links {
		if l.Path == path && l.UserID == id {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		return nil, fberrors.ErrNotExist
	}
	return out, nil
}

func (s shareBackend) Save(l *share.Link) error {
	raw, err := json.Marshal(l)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *boltapi.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(shareBucket))
		if err != nil {
			return err
		}
		return b.Put([]byte(l.Hash), raw)
	})
}

func (s shareBackend) Delete(hash string) error {
	return s.db.Update(func(tx *boltapi.Tx) error {
		b := tx.Bucket([]byte(shareBucket))
		if b == nil {
			return nil
		}
		return b.Delete([]byte(hash))
	})
}

func (s shareBackend) DeleteWithPathPrefix(pathPrefix string, userID uint) error {
	// Share paths are stored without a trailing slash
	prefix := strings.TrimRight(pathPrefix, "/")

	links, err := s.all()
	if err != nil {
		if errors.Is(err, fberrors.ErrNotExist) {
			return nil
		}
		return err
	}

	for _, link := range links {
		if link.UserID != userID {
			continue
		}

		if link.Path != prefix && !strings.HasPrefix(link.Path, prefix+"/") {
			continue
		}

		if err := s.Delete(link.Hash); err != nil {
			return err
		}
	}
	return nil
}
