package bolt

import (
	"encoding/binary"
	"encoding/json"

	boltapi "go.etcd.io/bbolt"

	fberrors "github.com/realalexandergeorgiev/filebrowser-ng/errors"
	"github.com/realalexandergeorgiev/filebrowser-ng/sessions"
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
		if err := b.Put([]byte(sess.JTI), raw); err != nil {
			return err
		}
		return reindexSessions(b)
	})
}

func (s sessionBackend) Delete(jti string) error {
	return s.db.Update(func(tx *boltapi.Tx) error {
		b := tx.Bucket([]byte(sessionBucket))
		if b == nil {
			return nil
		}
		if err := b.Delete([]byte(jti)); err != nil {
			return err
		}
		return reindexSessions(b)
	})
}

// reindexSessions rebuilds storm's index sub-buckets from the rows, so a
// rolled-back binary keeps finding post-migration sessions through indexed
// queries. Formats observed from storm writes: JTI index maps jti->jti,
// UserID index maps BE(userID)+"__"+jti -> jti.
func reindexSessions(b *boltapi.Bucket) error {
	jtiIdx, err := resetIndex(b, "__storm_index_JTI")
	if err != nil {
		return err
	}
	uidIdx, err := resetIndex(b, "__storm_index_UserID")
	if err != nil {
		return err
	}
	c := b.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if v == nil {
			continue
		}
		var sess sessions.Session
		if err := json.Unmarshal(v, &sess); err != nil {
			return err
		}
		if err := jtiIdx.Put([]byte(sess.JTI), []byte(sess.JTI)); err != nil {
			return err
		}
		uidKey := append(userIDBytes(sess.UserID), "__"+sess.JTI...)
		if err := uidIdx.Put(uidKey, []byte(sess.JTI)); err != nil {
			return err
		}
	}
	return nil
}

// resetIndex drops and recreates one storm index sub-bucket, including the
// sentinel storm writes into it.
func resetIndex(b *boltapi.Bucket, name string) (*boltapi.Bucket, error) {
	if err := b.DeleteBucket([]byte(name)); err != nil && err != boltapi.ErrBucketNotFound {
		return nil, err
	}
	idx, err := b.CreateBucket([]byte(name))
	if err != nil {
		return nil, err
	}
	if err := idx.Put([]byte("storm__ids"), []byte{}); err != nil {
		return nil, err
	}
	return idx, nil
}

func userIDBytes(id uint) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(id))
	return b[:]
}
