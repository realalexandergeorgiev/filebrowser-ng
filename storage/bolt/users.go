package bolt

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	boltapi "go.etcd.io/bbolt"

	fberrors "github.com/realalexandergeorgiev/filebrowser-ng/errors"
	"github.com/realalexandergeorgiev/filebrowser-ng/users"
)

// userBucket matches the storm bucket name for users.User, so rows written
// before the migration stay readable and rollbacks work. Keys are 8-byte
// big-endian IDs, values plain JSON. Storm's index sub-buckets are left
// alone: the table is tiny, so scans replace index lookups and there is no
// index state to maintain. IDs come from max+1 scans instead of a stored
// sequence, which cannot drift.
const userBucket = "User"

type usersBackend struct {
	db *boltapi.DB
}

func userKey(id uint) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(id))
	return b[:]
}

// rows reads every user row, skipping storm's index sub-buckets. A missing
// bucket reads as empty, matching the old behavior on fresh databases.
func (st usersBackend) rows(tx *boltapi.Tx) ([]*users.User, error) {
	var out []*users.User
	b := tx.Bucket([]byte(userBucket))
	if b == nil {
		return out, nil
	}
	err := b.ForEach(func(k, v []byte) error {
		if v == nil {
			return nil // index sub-bucket, not a user
		}
		var u users.User
		if err := json.Unmarshal(v, &u); err != nil {
			return err
		}
		out = append(out, &u)
		return nil
	})
	return out, err
}

func (st usersBackend) GetBy(i interface{}) (user *users.User, err error) {
	switch id := i.(type) {
	case uint:
		err := st.db.View(func(tx *boltapi.Tx) error {
			b := tx.Bucket([]byte(userBucket))
			if b == nil {
				return fberrors.ErrNotExist
			}
			raw := b.Get(userKey(id))
			if raw == nil {
				return fberrors.ErrNotExist
			}
			user = &users.User{}
			return json.Unmarshal(raw, user)
		})
		return user, err
	case string:
		var found *users.User
		err := st.db.View(func(tx *boltapi.Tx) error {
			all, err := st.rows(tx)
			if err != nil {
				return err
			}
			for _, u := range all {
				if u.Username == id {
					found = u
					return nil
				}
			}
			return fberrors.ErrNotExist
		})
		return found, err
	default:
		return nil, fberrors.ErrInvalidDataType
	}
}

func (st usersBackend) GetByScope(scope string) (*users.User, error) {
	var found *users.User
	err := st.db.View(func(tx *boltapi.Tx) error {
		all, err := st.rows(tx)
		if err != nil {
			return err
		}
		// Match case-insensitively: on a case-insensitive filesystem two
		// scopes that differ only in case resolve to the same home
		// directory, so they must be treated as a collision.
		for _, u := range all {
			if strings.EqualFold(u.Scope, scope) {
				found = u
				return nil
			}
		}
		return fberrors.ErrNotExist
	})
	return found, err
}

func (st usersBackend) Gets() ([]*users.User, error) {
	var out []*users.User
	err := st.db.View(func(tx *boltapi.Tx) error {
		all, err := st.rows(tx)
		if err != nil {
			return err
		}
		out = all
		return nil
	})
	return out, err
}

func (st usersBackend) Update(user *users.User, fields ...string) error {
	if len(fields) == 0 {
		return st.Save(user)
	}

	return st.db.Update(func(tx *boltapi.Tx) error {
		b := tx.Bucket([]byte(userBucket))
		if b == nil {
			return fberrors.ErrNotExist
		}
		raw := b.Get(userKey(user.ID))
		if raw == nil {
			return fberrors.ErrNotExist
		}
		current := &users.User{}
		if err := json.Unmarshal(raw, current); err != nil {
			return err
		}
		for _, field := range fields {
			src := reflect.ValueOf(user).Elem().FieldByName(field)
			if !src.IsValid() {
				return fmt.Errorf("invalid field: %s", field)
			}
			reflect.ValueOf(current).Elem().FieldByName(field).Set(src)
		}
		out, err := json.Marshal(current)
		if err != nil {
			return err
		}
		return b.Put(userKey(user.ID), out)
	})
}

func (st usersBackend) Save(user *users.User) error {
	return st.db.Update(func(tx *boltapi.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(userBucket))
		if err != nil {
			return err
		}
		if user.ID == 0 {
			user.ID = nextUserID(b)
		}
		// Usernames stay unique, as with the old unique index.
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if v == nil {
				continue
			}
			var u users.User
			if err := json.Unmarshal(v, &u); err != nil {
				return err
			}
			if u.Username == user.Username && u.ID != user.ID {
				return fberrors.ErrExist
			}
		}
		raw, err := json.Marshal(user)
		if err != nil {
			return err
		}
		if err := b.Put(userKey(user.ID), raw); err != nil {
			return err
		}
		return reindexUsers(b)
	})
}

// nextUserID assigns max+1 over existing rows, so IDs never collide with
// pre-migration rows regardless of any stored sequence.
func nextUserID(b *boltapi.Bucket) uint {
	var max uint
	c := b.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if v == nil || len(k) != 8 {
			continue
		}
		if id := uint(binary.BigEndian.Uint64(k)); id > max {
			max = id
		}
	}
	return max + 1
}

func (st usersBackend) DeleteByID(id uint) error {
	return st.db.Update(func(tx *boltapi.Tx) error {
		b := tx.Bucket([]byte(userBucket))
		if b == nil {
			return nil
		}
		if err := b.Delete(userKey(id)); err != nil {
			return err
		}
		return reindexUsers(b)
	})
}

func (st usersBackend) DeleteByUsername(username string) error {
	user, err := st.GetBy(username)
	if err != nil {
		return err
	}

	return st.DeleteByID(user.ID)
}

func (st usersBackend) CountAdmins() (int, error) {
	count := 0

	err := st.db.View(func(tx *boltapi.Tx) error {
		all, err := st.rows(tx)
		if err != nil {
			return err
		}
		for _, u := range all {
			if u.Perm.Admin {
				count++
			}
		}

		return nil
	})

	return count, err
}

// reindexUsers rebuilds storm's index sub-buckets and the ID counter from
// the rows, so a rolled-back binary keeps finding post-migration users
// through indexed queries and never reuses an ID. Formats observed from
// storm writes: ID index maps BE(id)->BE(id), Username index maps
// username->BE(id), metadata holds IDcounter as BE uint.
func reindexUsers(b *boltapi.Bucket) error {
	idIdx, err := resetIndex(b, "__storm_index_ID")
	if err != nil {
		return err
	}
	nameIdx, err := resetIndex(b, "__storm_index_Username")
	if err != nil {
		return err
	}
	var max uint
	c := b.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if v == nil {
			continue
		}
		var u users.User
		if err := json.Unmarshal(v, &u); err != nil {
			return err
		}
		key := userKey(u.ID)
		if err := idIdx.Put(key, key); err != nil {
			return err
		}
		if err := nameIdx.Put([]byte(u.Username), key); err != nil {
			return err
		}
		if u.ID > max {
			max = u.ID
		}
	}
	meta, err := b.CreateBucketIfNotExists([]byte("__storm_metadata"))
	if err != nil {
		return err
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(max))
	return meta.Put([]byte("IDcounter"), counter[:])
}
