# filebrowser-ng completion zsh

Generate the autocompletion script for zsh

## Synopsis

Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

	echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions in your current shell session:

	source <(filebrowser-ng completion zsh)

To load completions for every new session, execute once:

### Linux:

	filebrowser-ng completion zsh > "${fpath[1]}/_filebrowser-ng"

### macOS:

	filebrowser-ng completion zsh > $(brew --prefix)/share/zsh/site-functions/_filebrowser-ng

You will need to start a new shell for this setup to take effect.


```
filebrowser-ng completion zsh [flags]
```

## Options

```
  -h, --help              help for zsh
      --no-descriptions   disable completion descriptions
```

## Options inherited from parent commands

```
  -c, --config string     config file path
  -d, --database string   database path (default "./filebrowser.db")
```

## See Also

* [filebrowser-ng completion](filebrowser-ng-completion.md)	 - Generate the autocompletion script for the specified shell

