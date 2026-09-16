package sessions

// Server-side sessions for filebrowser-ng.
//
// The v2 baseline used self-contained JWTs that could not be revoked:
// logout, password changes and user deletion left previously issued tokens
// valid until expiry, and /renew re-issued from any valid token forever
// (#5216, GO-2025-3812/CVE-2025-53826).
//
// Every access token now carries the session ID (JWT jti). The HTTP layer
// refuses tokens whose session is unknown or expired, and revokes sessions
// on logout, password/security changes and user deletion. Access tokens stay
// short-lived; renewing slides the session expiry up to MaxLifetime, after
// which the user must log in again.
import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	fberrors "github.com/filebrowser/filebrowser/v2/errors"
)

// MaxLifetime bounds the sliding session lifetime from creation, no matter
// how often it is renewed. MaxSessionsPerUser bounds stored sessions per user.
const (
	MaxLifetime        = 30 * 24 * time.Hour
	MaxSessionsPerUser = 50
)

// ErrExpired reports a session that passed MaxLifetime (or its expiry).
// It maps to 401 and forces a fresh login.
var ErrExpired = errors.New("session expired")

// Session is one login. Stored server-side; the client only holds the
// random JTI inside its access token.
type Session struct {
	JTI       string `storm:"id" json:"jti"`
	UserID    uint   `storm:"index" json:"userId"`
	CreatedAt int64  `json:"createdAt"`
	ExpiresAt int64  `json:"expiresAt"`
}

// Expired reports whether the session must no longer be honored.
func (s *Session) Expired(now time.Time) bool {
	return now.Unix() >= s.ExpiresAt || now.Unix() >= s.CreatedAt+int64(MaxLifetime.Seconds())
}

// StorageBackend is implemented by the database layer.
type StorageBackend interface {
	Get(jti string) (*Session, error)
	FindByUserID(id uint) ([]*Session, error)
	Save(s *Session) error
	Delete(jti string) error
}

// Storage wraps a StorageBackend with creation, sliding renewal and
// revocation. It never trusts client input beyond the opaque JTI.
type Storage struct {
	back StorageBackend
}

// NewStorage creates a session storage from a backend.
func NewStorage(back StorageBackend) *Storage {
	return &Storage{back: back}
}

// Create opens a session for userID with a sliding expiry of ttl, capped by
// MaxLifetime. It opportunistically prunes the user's expired sessions and
// caps the stored count so repeated logins cannot grow the table forever.
func (s *Storage) Create(userID uint, ttl time.Duration) (*Session, error) {
	now := time.Now()
	sess := &Session{
		JTI:       newJTI(),
		UserID:    userID,
		CreatedAt: now.Unix(),
		ExpiresAt: now.Add(minDuration(ttl, MaxLifetime)).Unix(),
	}
	if err := s.back.Save(sess); err != nil {
		return nil, err
	}
	s.prune(userID, now)
	return sess, nil
}

// Get returns the live session for jti, or an error when unknown.
func (s *Storage) Get(jti string) (*Session, error) {
	return s.back.Get(jti)
}

// Touch slides the expiry of a live session by ttl, capped by MaxLifetime
// from creation. Revoked (unknown) sessions stay unknown; sessions past
// MaxLifetime are deleted and reported as ErrExpired.
func (s *Storage) Touch(jti string, ttl time.Duration) (*Session, error) {
	now := time.Now()
	sess, err := s.back.Get(jti)
	if err != nil {
		return nil, err
	}
	if now.Unix() >= sess.CreatedAt+int64(MaxLifetime.Seconds()) {
		_ = s.back.Delete(jti)
		return nil, ErrExpired
	}
	sess.ExpiresAt = now.Add(minDuration(ttl, time.Until(time.Unix(sess.CreatedAt, 0).Add(MaxLifetime)))).Unix()
	if err := s.back.Save(sess); err != nil {
		return nil, err
	}
	return sess, nil
}

// Revoke deletes one session. Unknown JTIs are not an error, so logout is
// idempotent.
func (s *Storage) Revoke(jti string) error {
	return s.back.Delete(jti)
}

// RevokeUser deletes all sessions of a user: password/security changes,
// admin revocation and user deletion take effect immediately.
func (s *Storage) RevokeUser(id uint) error {
	sessions, err := s.back.FindByUserID(id)
	if errors.Is(err, fberrors.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, sess := range sessions {
		if err := s.back.Delete(sess.JTI); err != nil {
			return err
		}
	}
	return nil
}

// prune drops expired sessions of a user and, if still over the per-user
// cap, the oldest ones. Best effort: creation already succeeded.
func (s *Storage) prune(id uint, now time.Time) {
	sessions, err := s.back.FindByUserID(id)
	if errors.Is(err, fberrors.ErrNotExist) {
		return
	}
	if err != nil {
		return
	}
	var live []*Session
	for _, sess := range sessions {
		if sess.Expired(now) {
			_ = s.back.Delete(sess.JTI)
			continue
		}
		live = append(live, sess)
	}
	for len(live) > MaxSessionsPerUser {
		oldest := 0
		for i := range live {
			if live[i].CreatedAt < live[oldest].CreatedAt {
				oldest = i
			}
		}
		_ = s.back.Delete(live[oldest].JTI)
		live = append(live[:oldest], live[oldest+1:]...)
	}
}

func newJTI() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("sessions: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
