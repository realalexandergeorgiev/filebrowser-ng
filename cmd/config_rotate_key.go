package cmd

import (
	"github.com/spf13/cobra"

	"github.com/realalexandergeorgiev/filebrowser-ng/settings"
)

func init() {
	configCmd.AddCommand(configRotateKeyCmd)
}

var configRotateKeyCmd = &cobra.Command{
	Use:   "rotate-key",
	Short: "Generate a new signing key, invalidating all tokens",
	Long: `Generate a new random signing key and store it.

All previously issued access tokens fail signature verification at
once, which ends every login session everywhere. Use this when the key
may have leaked (for example via an old config export).`,
	Args: cobra.NoArgs,
	RunE: withStore(func(_ *cobra.Command, _ []string, st *store) error {
		return rotateSettingsKey(st.Settings)
	}, storeOptions{}),
}

// rotateSettingsKey replaces the JWT signing key. Token signatures made
// with the old key stop verifying, so no extra session cleanup is needed
// to lock everyone out.
func rotateSettingsKey(s *settings.Storage) error {
	set, err := s.Get()
	if err != nil {
		return err
	}
	set.Key = generateKey()
	return s.Save(set)
}
