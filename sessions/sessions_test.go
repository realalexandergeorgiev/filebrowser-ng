package sessions

import (
	"errors"
	"testing"
	"time"

	fberrors "github.com/realalexandergeorgiev/filebrowser-ng/errors"
)

type stubBackend struct {
	m map[string]*Session
}

func newStub() *stubBackend { return &stubBackend{m: map[string]*Session{}} }

func (b *stubBackend) Get(jti string) (*Session, error) {
	s, ok := b.m[jti]
	if !ok {
		return nil, fberrors.ErrNotExist
	}
	cp := *s
	return &cp, nil
}

func (b *stubBackend) FindByUserID(id uint) ([]*Session, error) {
	var out []*Session
	for _, s := range b.m {
		if s.UserID == id {
			cp := *s
			out = append(out, &cp)
		}
	}
	if len(out) == 0 {
		return nil, fberrors.ErrNotExist
	}
	return out, nil
}

func (b *stubBackend) Save(s *Session) error {
	cp := *s
	b.m[s.JTI] = &cp
	return nil
}

func (b *stubBackend) Delete(jti string) error {
	delete(b.m, jti)
	return nil
}

func TestCreateIssuesUniqueLiveSession(t *testing.T) {
	st := NewStorage(newStub())
	a, err := st.Create(1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, err := st.Create(1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if a.JTI == "" || a.JTI == b.JTI {
		t.Fatalf("JTIs must be unique non-empty, got %q and %q", a.JTI, b.JTI)
	}
	if got, err := st.Get(a.JTI); err != nil || got.UserID != 1 {
		t.Fatalf("Get = %+v, %v", got, err)
	}
}

func TestTouchSlidesExpiryCappedByMaxLifetime(t *testing.T) {
	back := newStub()
	st := NewStorage(back)
	sess, err := st.Create(1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	first := sess.ExpiresAt
	moved, err := st.Touch(sess.JTI, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if moved.ExpiresAt < first {
		t.Fatalf("Touch must slide expiry forward: %d -> %d", first, moved.ExpiresAt)
	}

	// A session past MaxLifetime cannot be revived.
	old := &Session{JTI: "old", UserID: 1, CreatedAt: time.Now().Add(-MaxLifetime - time.Hour).Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix()}
	if err := back.Save(old); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Touch("old", time.Hour); !errors.Is(err, ErrExpired) {
		t.Fatalf("Touch past MaxLifetime = %v, want ErrExpired", err)
	}
	if _, err := st.Get("old"); !errors.Is(err, fberrors.ErrNotExist) {
		t.Fatalf("expired session must be deleted, Get = %v", err)
	}
}

func TestRevokeAndRevokeUser(t *testing.T) {
	back := newStub()
	st := NewStorage(back)
	a, _ := st.Create(1, time.Hour)
	b, _ := st.Create(1, time.Hour)
	c, _ := st.Create(2, time.Hour)

	if err := st.Revoke(a.JTI); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get(a.JTI); !errors.Is(err, fberrors.ErrNotExist) {
		t.Fatalf("revoked session still resolvable: %v", err)
	}
	// Revoke is idempotent.
	if err := st.Revoke(a.JTI); err != nil {
		t.Fatalf("second Revoke = %v", err)
	}

	if err := st.RevokeUser(1); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get(b.JTI); !errors.Is(err, fberrors.ErrNotExist) {
		t.Fatalf("user session survived RevokeUser: %v", err)
	}
	if _, err := st.Get(c.JTI); err != nil {
		t.Fatalf("other user's session must survive: %v", err)
	}
	// Revoking a user without sessions is not an error.
	if err := st.RevokeUser(99); err != nil {
		t.Fatalf("RevokeUser without sessions = %v", err)
	}
}

func TestCreatePrunesExpired(t *testing.T) {
	back := newStub()
	st := NewStorage(back)
	past := time.Now().Add(-2 * time.Hour).Unix()
	if err := back.Save(&Session{JTI: "dead", UserID: 7, CreatedAt: past, ExpiresAt: past}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Create(7, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get("dead"); !errors.Is(err, fberrors.ErrNotExist) {
		t.Fatalf("expired session survived Create prune: %v", err)
	}
}
