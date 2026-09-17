package cmd

import (
	"testing"

	"github.com/realalexandergeorgiev/filebrowser-ng/users"
)

func TestCheckAdminBootstrap(t *testing.T) {
	admin := &users.User{Username: "a"}
	admin.Perm.Admin = true
	plain := &users.User{Username: "u"}

	for _, tc := range []struct {
		name       string
		all        []*users.User
		addedAdmin bool
		want       bool
	}{
		{"first non-admin user warns", []*users.User{plain}, false, true},
		{"empty store adding plain user warns", nil, false, true},
		{"adding an admin never warns", nil, true, false},
		{"existing admin silences the warning", []*users.User{admin, plain}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := checkAdminBootstrap(tc.all, tc.addedAdmin); got != tc.want {
				t.Errorf("checkAdminBootstrap = %v, want %v", got, tc.want)
			}
		})
	}
}
