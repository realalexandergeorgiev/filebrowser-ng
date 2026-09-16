package bolt

import (
	boltapi "go.etcd.io/bbolt"

	"github.com/filebrowser/filebrowser/v2/settings"
)

type settingsBackend struct {
	db *boltapi.DB
}

func (s settingsBackend) Get() (*settings.Settings, error) {
	set := &settings.Settings{}
	return set, kvGet(s.db, "settings", set)
}

func (s settingsBackend) Save(set *settings.Settings) error {
	return kvPut(s.db, "settings", set)
}

func (s settingsBackend) GetServer() (*settings.Server, error) {
	server := &settings.Server{}
	return server, kvGet(s.db, "server", server)
}

func (s settingsBackend) SaveServer(server *settings.Server) error {
	return kvPut(s.db, "server", server)
}
