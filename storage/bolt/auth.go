package bolt

import (
	"encoding/json"

	boltapi "go.etcd.io/bbolt"

	"github.com/realalexandergeorgiev/filebrowser-ng/auth"
	fberrors "github.com/realalexandergeorgiev/filebrowser-ng/errors"
	"github.com/realalexandergeorgiev/filebrowser-ng/settings"
)

// configBucket and the "auther" key match the storm key/value layout, so
// rows written before the migration stay readable and rollbacks work.
// The bucket stays shared with the settings backend until it migrates too.
const configBucket = "config"

type authBackend struct {
	db *boltapi.DB
}

func (s authBackend) Get(t settings.AuthMethod) (auth.Auther, error) {
	var auther auth.Auther

	switch t {
	case auth.MethodJSONAuth:
		auther = &auth.JSONAuth{}
	case auth.MethodProxyAuth:
		auther = &auth.ProxyAuth{}
	case auth.MethodNoAuth:
		auther = &auth.NoAuth{}
	default:
		return nil, fberrors.ErrInvalidAuthMethod
	}

	err := s.db.View(func(tx *boltapi.Tx) error {
		b := tx.Bucket([]byte(configBucket))
		if b == nil {
			return fberrors.ErrNotExist
		}
		raw := b.Get([]byte("auther"))
		if raw == nil {
			return fberrors.ErrNotExist
		}
		return json.Unmarshal(raw, auther)
	})
	if err != nil {
		return nil, err
	}

	return auther, nil
}

func (s authBackend) Save(a auth.Auther) error {
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *boltapi.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(configBucket))
		if err != nil {
			return err
		}
		return b.Put([]byte("auther"), raw)
	})
}
