package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/realalexandergeorgiev/filebrowser-ng/version"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Println("filebrowser-ng v" + version.Version + "/" + version.CommitSHA)
	},
}
