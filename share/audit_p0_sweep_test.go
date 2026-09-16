package share

// Audit characterization for H-share expiry sweep (ARCHITEKTUR.md §3,
// share/storage.go:39-46,59-66,101-108): All/FindByUserID/Gets delete expired
// links while ranging over the same slice
// (`links = append(links[:i], links[i+1:]...)` inside `for i, link := range links`),
// so consecutive expiries are skipped and stay listed + stored.
//
// Pinned v2 behavior: [expiredA, expiredB, validC].All() still returns an
// expired link. filebrowser-ng target: no expired link is returned or kept;
// flip this test to assert zero expired links when the sweeper is fixed.
import (
	"errors"
	"testing"
	"time"

	fberrors "github.com/filebrowser/filebrowser/v2/errors"
)

type auditStubBackend struct {
	links []*Link
}

func (b *auditStubBackend) All() ([]*Link, error) {
	out := make([]*Link, len(b.links))
	copy(out, b.links)
	return out, nil
}

func (b *auditStubBackend) FindByUserID(id uint) ([]*Link, error) { return b.All() }
func (b *auditStubBackend) GetByHash(hash string) (*Link, error) {
	for _, l := range b.links {
		if l.Hash == hash {
			return l, nil
		}
	}
	return nil, fberrors.ErrNotExist
}
func (b *auditStubBackend) GetPermanent(_ string, _ uint) (*Link, error) {
	return nil, errors.New("not implemented")
}
func (b *auditStubBackend) Gets(_ string, _ uint) ([]*Link, error) { return b.All() }
func (b *auditStubBackend) Save(l *Link) error {
	b.links = append(b.links, l)
	return nil
}
func (b *auditStubBackend) Delete(hash string) error {
	for i, l := range b.links {
		if l.Hash == hash {
			b.links = append(b.links[:i], b.links[i+1:]...)
			return nil
		}
	}
	return fberrors.ErrNotExist
}
func (b *auditStubBackend) DeleteWithPathPrefix(_ string, _ uint) error { return nil }

func TestAuditExpirySweepSkipsConsecutiveExpired(t *testing.T) {
	past := time.Now().Add(-time.Hour).Unix()
	back := &auditStubBackend{links: []*Link{
		{Hash: "expiredA", Expire: past},
		{Hash: "expiredB", Expire: past},
		{Hash: "validC", Expire: 0},
	}}
	got, err := NewStorage(back).All()
	if err != nil {
		t.Fatalf("All failed: %v", err)
	}
	expired := 0
	for _, l := range got {
		if l.Expire != 0 && l.Expire <= time.Now().Unix() {
			expired++
		}
	}
	if expired == 0 {
		t.Fatalf("AUDIT CHANGED: no expired link survived All(); v2 baseline leaks at least one, ng target leaks zero")
	}
	t.Logf("pinned v2 behavior: %d expired link(s) still listed (want 0 after fix)", expired)
}
