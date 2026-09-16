package bolt

import (
	"encoding/json"

	boltapi "go.etcd.io/bbolt"

	fberrors "github.com/realalexandergeorgiev/filebrowser-ng/errors"
)

// kvGet/kvPut are the raw replacements for the storm key/value helpers:
// plain JSON under one key in the shared config bucket, readable both ways.
func kvGet(db *boltapi.DB, key string, to interface{}) error {
	err := db.View(func(tx *boltapi.Tx) error {
		b := tx.Bucket([]byte(configBucket))
		if b == nil {
			return fberrors.ErrNotExist
		}
		raw := b.Get([]byte(key))
		if raw == nil {
			return fberrors.ErrNotExist
		}
		return json.Unmarshal(raw, to)
	})
	return err
}

func kvPut(db *boltapi.DB, key string, from interface{}) error {
	raw, err := json.Marshal(from)
	if err != nil {
		return err
	}
	return db.Update(func(tx *boltapi.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(configBucket))
		if err != nil {
			return err
		}
		return b.Put([]byte(key), raw)
	})
}
