package main

import (
	"os"

	"github.com/realalexandergeorgiev/filebrowser-ng/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
