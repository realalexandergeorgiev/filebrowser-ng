# filebrowser config rotate-key

Generate a new signing key, invalidating all tokens

## Synopsis

Generate a new random signing key and store it.

All previously issued access tokens fail signature verification at
once, which ends every login session everywhere. Use this when the key
may have leaked (for example via an old config export).

```
filebrowser config rotate-key [flags]
```

## Options

```
  -h, --help   help for rotate-key
```

## Options inherited from parent commands

```
  -c, --config string     config file path
  -d, --database string   database path (default "./filebrowser.db")
```

## See Also

* [filebrowser config](filebrowser-config.md)	 - Configuration management utility

