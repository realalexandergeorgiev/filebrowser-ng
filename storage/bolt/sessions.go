package bolt

import (
	"errors"

	"github.com/asdine/storm/v3"
	"github.com/asdine/storm/v3/q"

	fberrors "github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/sessions"
)

type sessionBackend struct {
	db *storm.DB
}

func (s sessionBackend) Get(jti string) (*sessions.Session, error) {
	var v sessions.Session
	err := s.db.One("JTI", jti, &v)
	if errors.Is(err, storm.ErrNotFound) {
		return nil, fberrors.ErrNotExist
	}
	return &v, err
}

func (s sessionBackend) FindByUserID(id uint) ([]*sessions.Session, error) {
	var v []*sessions.Session
	err := s.db.Select(q.Eq("UserID", id)).Find(&v)
	if errors.Is(err, storm.ErrNotFound) {
		return v, fberrors.ErrNotExist
	}
	return v, err
}

func (s sessionBackend) Save(sess *sessions.Session) error {
	return s.db.Save(sess)
}

func (s sessionBackend) Delete(jti string) error {
	err := s.db.DeleteStruct(&sessions.Session{JTI: jti})
	if errors.Is(err, storm.ErrNotFound) {
		return nil
	}
	return err
}
