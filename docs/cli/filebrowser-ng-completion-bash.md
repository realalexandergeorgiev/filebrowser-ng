# filebrowser-ng completion bash

Generate the autocompletion script for bash

## Synopsis

Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package manager.

To load completions in your current shell session:

	source <(filebrowser-ng completion bash)

To load completions for every new session, execute once:

### Linux:

	filebrowser-ng completion bash > /etc/bash_completion.d/filebrowser-ng

### macOS:

	filebrowser-ng completion bash > $(brew --prefix)/etc/bash_completion.d/filebrowser-ng

You will need to start a new shell for this setup to take effect.


```
filebrowser-ng completion bash
```

## Options

```
  -h, --help              help for bash
      --no-descriptions   disable completion descriptions
```

## Options inherited from parent commands

```
  -c, --config string     config file path
  -d, --database string   database path (default "./filebrowser.db")
```

## See Also

* [filebrowser-ng completion](filebrowser-ng-completion.md)	 - Generate the autocompletion script for the specified shell

