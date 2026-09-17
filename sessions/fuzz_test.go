package sessions

import (
	"math"
	"testing"
	"time"
)

// FuzzSessionExpired pins the expiry math: a session is expired exactly
// from its expiry timestamp or MaxLifetime after creation on, and expiry
// is monotonic in time (a live session never dies going backwards).
func FuzzSessionExpired(f *testing.F) {
	for _, seed := range [][3]int64{
		{1000, 2000, 1500}, {1000, 2000, 2000}, {1000, 2000, 500},
		{0, 0, 0}, {math.MaxInt64 - 1, math.MaxInt64 - 1, 0},
	} {
		f.Add(seed[0], seed[1], seed[2])
	}
	f.Fuzz(func(t *testing.T, created, expires, now int64) {
		if now == math.MaxInt64 {
			t.Skip("avoids now+1 overflow in the monotonicity check")
		}
		s := &Session{CreatedAt: created, ExpiresAt: expires}
		got := s.Expired(time.Unix(now, 0))
		want := now >= expires || now >= created+int64(MaxLifetime.Seconds())
		if got != want {
			t.Fatalf("Expired(created=%d, expires=%d, now=%d) = %v, want %v",
				created, expires, now, got, want)
		}
		if got && !s.Expired(time.Unix(now+1, 0)) {
			t.Fatalf("expiry not monotonic at now=%d", now)
		}
	})
}

// FuzzCreatePruneCap hammers session creation for one user: the stored
// count must stay capped so repeated logins cannot grow the table forever,
// and every issued JTI must be unique and look well-formed.
func FuzzCreatePruneCap(f *testing.F) {
	f.Add(0)
	f.Add(1)
	f.Add(51)
	f.Add(200)
	f.Fuzz(func(t *testing.T, n int) {
		if n < 0 || n > 500 {
			t.Skip("keeps the test fast; the cap is far below")
		}
		back := newStub()
		st := NewStorage(back)
		seen := map[string]bool{}
		for i := 0; i < n; i++ {
			s, err := st.Create(7, time.Hour)
			if err != nil {
				t.Fatalf("create %d: %v", i, err)
			}
			if len(s.JTI) != 32 {
				t.Fatalf("JTI %q has length %d, want 32 hex chars", s.JTI, len(s.JTI))
			}
			for _, c := range s.JTI {
				if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
					t.Fatalf("JTI %q is not lowercase hex", s.JTI)
				}
			}
			if seen[s.JTI] {
				t.Fatalf("duplicate JTI %q", s.JTI)
			}
			seen[s.JTI] = true
		}
		if len(back.m) > MaxSessionsPerUser {
			t.Fatalf("stored %d sessions, want at most %d", len(back.m), MaxSessionsPerUser)
		}
	})
}
