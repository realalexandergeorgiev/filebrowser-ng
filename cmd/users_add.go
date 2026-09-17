package cmd

import (
	"log"

	"github.com/spf13/cobra"

	"github.com/realalexandergeorgiev/filebrowser-ng/users"
)

func init() {
	usersCmd.AddCommand(usersAddCmd)
	addUserFlags(usersAddCmd.Flags())
}

var usersAddCmd = &cobra.Command{
	Use:   "add <username> <password>",
	Short: "Create a new user",
	Long:  `Create a new user and add it to the database.`,
	Args:  cobra.ExactArgs(2),
	RunE: withStore(func(cmd *cobra.Command, args []string, st *store) error {
		flags := cmd.Flags()
		s, err := st.Settings.Get()
		if err != nil {
			return err
		}
		err = getUserDefaults(flags, &s.Defaults, false)
		if err != nil {
			return err
		}

		password, err := users.ValidateAndHashPwd(args[1], s.MinimumPasswordLength)
		if err != nil {
			return err
		}

		user := &users.User{
			Username: args[0],
			Password: password,
		}

		user.LockPassword, err = flags.GetBool("lockPassword")
		if err != nil {
			return err
		}

		user.DateFormat, err = flags.GetBool("dateFormat")
		if err != nil {
			return err
		}

		user.HideDotfiles, err = flags.GetBool("hideDotfiles")
		if err != nil {
			return err
		}

		s.Defaults.Apply(user)

		servSettings, err := st.Settings.GetServer()
		if err != nil {
			return err
		}
		// since getUserDefaults() polluted s.Defaults.Scope
		// which makes the Scope not the one saved in the db
		// we need the right s.Defaults.Scope here
		s2, err := st.Settings.Get()
		if err != nil {
			return err
		}

		userHome, err := s2.MakeUserDir(user.Username, user.Scope, servSettings.Root)
		if err != nil {
			return err
		}
		user.Scope = userHome

		err = st.Users.Save(user)
		if err != nil {
			return err
		}
		printUsers([]*users.User{user})
		if list, err := st.Users.Gets("", false); err == nil && checkAdminBootstrap(list, user.Perm.Admin) {
			log.Printf("WARNING: no admin user exists. Re-run with --perm.admin to create one, or settings and user management stay unreachable.")
		}
		return nil
	}, storeOptions{}),
}

// checkAdminBootstrap reports whether adding a non-admin user leaves the
// instance without any administrator. Fresh installs via `users add`
// default to non-admin, so the first user usually triggers this. The
// command only warns instead of failing: automation may create the admin
// separately (e.g. quick setup does).
func checkAdminBootstrap(all []*users.User, addedAdmin bool) bool {
	if addedAdmin {
		return false
	}
	for _, u := range all {
		if u.Perm.Admin {
			return false
		}
	}
	return true
}
