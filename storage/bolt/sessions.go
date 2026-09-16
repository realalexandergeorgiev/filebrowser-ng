package bolt

import (
	"encoding/json"

	boltapi "go.etcd.io/bbolt"

	fberrors "github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/sessions"
)

// sessionBucket matches the storm bucket name for sessions.Session, so rows
// written before the migration stay readable and rollbacks keep working.
// Storm's __storm_index_* sub-buckets are left alone: nothing reads them
// once this backend owns the bucket.
const sessionBucket = "Session"

type sessionBackend struct {
	db *boltapi.DB
}

func (s sessionBackend) Get(jti string) (*sessions.Session, error) {
	var v sessions.Session
	err := s.db.View(func(tx *boltapi.Tx) error {
		b := tx.Bucket([]byte(sessionBucket))
		if b == nil {
			return fberrors.ErrNotExist
		}
		raw := b.Get([]byte(jti))
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

func (s sessionBackend) FindByUserID(id uint) ([]*sessions.Session, error) {
	var out []*sessions.Session
	err := s.db.View(func(tx *boltapi.Tx) error {
		b := tx.Bucket([]byte(sessionBucket))
		if b == nil {
			return fberrors.ErrNotExist
		}
		return b.ForEach(func(k, v []byte) error {
			if v == nil {
				return nil // index sub-bucket, not a session
			}
			var sess sessions.Session
			if err := json.Unmarshal(v, &sess); err != nil {
				return err
			}
			if sess.UserID == id {
				out = append(out, &sess)
			}
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

func (s sessionBackend) Save(sess *sessions.Session) error {
	raw, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *boltapi.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(sessionBucket))
		if err != nil {
			return err
		}
		return b.Put([]byte(sess.JTI), raw)
	})
}

func (s sessionBackend) Delete(jti string) error {
	return s.db.Update(func(tx *boltapi.Tx) error {
		b := tx.Bucket([]byte(sessionBucket))
		if b == nil {
			return nil
		}
		return b.Delete([]byte(jti))
	})
}
