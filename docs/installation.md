# Installation

filebrowser-ng is a single binary and can be used as standalone executable. However, it is also available as a [Docker](https://www.docker.com) image. The installation and first time setup is quite straightforward independently of which system you use.

## Binary

Download the binary for your platform from the [releases page](https://github.com/realalexandergeorgiev/filebrowser-ng/releases)
(`filebrowser-ng_<os>_<arch>` plus `checksums.txt`; verify with
`sha256sum -c checksums.txt`), then:

```sh
./filebrowser-ng -r /path/to/your/files
```

There is no package manager tap or install script for this fork (yet);
the upstream ones below install upstream v2, not filebrowser-ng.

### Brew

```sh
brew tap filebrowser/tap
brew install filebrowser
filebrowser -r /path/to/your/files
```

### Unix

```sh
curl -fsSL https://raw.githubusercontent.com/filebrowser/get/master/get.sh | bash
filebrowser -r /path/to/your/files
```

### Windows

```sh
iwr -useb https://raw.githubusercontent.com/filebrowser/get/master/get.ps1 | iex
filebrowser -r /path/to/your/files
```

filebrowser-ng is now up and running. Read the ["First Boot"](#first-boot) section for more information.

## Docker

filebrowser-ng is available as two different Docker images, built locally
from this repository (`Dockerfile` for a bare Alpine image and
`Dockerfile.s6` for an S6 Overlay image — there is no published registry
image for this fork yet): a [bare Alpine image](#bare-alpine-image) and an [S6 Overlay image](#s6-overlay-image).

### Bare Alpine Image

```sh
docker run \
    -v filebrowser_data:/srv \
    -v filebrowser_database:/database \
    -v filebrowser_config:/config \
    -p 8080:80 \
    filebrowser-ng
```

Where `filebrowser_data`, `filebrowser_database` and `filebrowser_config` are Docker [volumes](https://docs.docker.com/engine/storage/volumes/), where the data, database and configuration will be stored, respectively. The default configuration and database will be automatically initialized.

The default user that runs filebrowser-ng inside the container has UID 1000 and GID 1000. If, for one reason or another, you want to run the Docker container with a different user, please consult Docker's [user documentation](https://docs.docker.com/engine/containers/run/#user).

> [!NOTE]
>
> When using [bind mounts](https://docs.docker.com/engine/storage/bind-mounts/), that is, when you mount a path on the host in the container, you must manually ensure that they have the correct **permissions**. Docker does not do this automatically for you. The host directories must be readable and writable by the user running inside the container. You can use the [`chown`](https://linux.die.net/man/1/chown) command to change the owner of those paths.

filebrowser-ng is now up and running. Read the ["First Boot"](#first-boot) section for more information.

### S6 Overlay Image

The `s6` image is based on LinuxServer and leverages the [s6-overlay](https://github.com/just-containers/s6-overlay) system for a standard, highly customizable image. It should be used as follows:

```shell
docker run \
    -v /path/to/srv:/srv \
    -v /path/to/database:/database \
    -v /path/to/config:/config \
    -e PUID=$(id -u) \
    -e PGID=$(id -g) \
    -p 8080:80 \
    filebrowser-ng:s6
```

Where:

- `/path/to/srv` contains the files root directory for filebrowser-ng
- `/path/to/config` contains a `settings.json` file
- `/path/to/database` contains a `filebrowser.db` file

Both `settings.json` and `filebrowser.db` will automatically be initialized if they don't exist.

filebrowser-ng is now up and running. Read the ["First Boot"](#first-boot) section for more information.

## First Boot

Your instance is now up and running. filebrowser-ng will automatically bootstrap a database, in which the configuration and the users are stored. You can find the address in which your instance is running, as well as the randomly generated password for the user `admin`, in the console logs.

> [!WARNING]
>
> The automatically generated password for the user `admin` is only displayed once. If you fail to remember it, you will need to manually delete the database and start filebrowser-ng again.

Although this is the fastest way to bootstrap an instance, we recommend you to take a look at other possible options, by checking [`config init`](cli/filebrowser-config-init.md) and [`config set`](cli/filebrowser-config-set.md), to make the installation as safe and customized as it can be.

If your goal is to have a public-facing deployment, we recommend taking a look at the [deployment](deployment.md) page for more information on how you can secure your installation.
