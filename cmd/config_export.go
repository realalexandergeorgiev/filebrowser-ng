package cmd

import (
	"log"

	"github.com/spf13/cobra"

	"github.com/realalexandergeorgiev/filebrowser-ng/settings"
)

func init() {
	configCmd.AddCommand(configExportCmd)
}

// withoutKey returns a copy of s with the signing key removed. The key
// forges admin JWTs, so it must never land in an export file; import
// already keeps the database key (or generates one), so nothing is lost.
func withoutKey(s *settings.Settings) *settings.Settings {
	out := *s
	out.Key = nil
	return &out
}

var configExportCmd = &cobra.Command{
	Use:   "export <path>",
	Short: "Export the configuration to a file",
	Long: `Export the configuration to a file. The path must be for a
json or yaml file. This exported configuration can be changed,
and imported again with 'config import' command.`,
	Args: jsonYamlArg,
	RunE: withStore(func(_ *cobra.Command, args []string, st *store) error {
		settings, err := st.Settings.Get()
		if err != nil {
			return err
		}

		server, err := st.Settings.GetServer()
		if err != nil {
			return err
		}

		auther, err := st.Auth.Get(settings.AuthMethod)
		if err != nil {
			return err
		}

		data := &settingsFile{
			Settings: withoutKey(settings),
			Auther:   auther,
			Server:   server,
		}

		err = marshal(args[0], data)
		if err != nil {
			return err
		}
		log.Printf("exported configuration to %s (signing key redacted; the file still holds auther credentials, keep it private)", args[0])
		return nil
	}, storeOptions{}),
}
