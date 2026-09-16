package fbhttp

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	gopath "path"
	"path/filepath"
	"strings"

	"github.com/realalexandergeorgiev/filebrowser-ng/files"
	"github.com/realalexandergeorgiev/filebrowser-ng/fileutils"
	"github.com/realalexandergeorgiev/filebrowser-ng/users"
)

func parseQueryFiles(r *http.Request, f *files.FileInfo, _ *users.User) ([]string, error) {
	var fileSlice []string
	names := strings.Split(r.URL.Query().Get("files"), ",")

	if len(names) == 0 {
		fileSlice = append(fileSlice, f.Path)
	} else {
		for _, name := range names {
			name, err := url.QueryUnescape(strings.ReplaceAll(name, "+", "%2B"))
			if err != nil {
				return nil, err
			}

			name = slashClean(name)
			fileSlice = append(fileSlice, filepath.Join(f.Path, name))
		}
	}

	return fileSlice, nil
}

// archiveFormat is a supported download packing. Only stdlib formats are
// offered: the exotic codecs (bz2, xz, lz4, sz, br, zst) came from an
// unmaintained dependency and are rejected.
type archiveFormat string

const (
	archiveZip   archiveFormat = "zip"
	archiveTar   archiveFormat = "tar"
	archiveTarGz archiveFormat = "targz"
)

func parseQueryAlgorithm(r *http.Request) (string, archiveFormat, error) {
	switch r.URL.Query().Get("algo") {
	case "zip", "true", "":
		return ".zip", archiveZip, nil
	case "tar":
		return ".tar", archiveTar, nil
	case "targz":
		return ".tar.gz", archiveTarGz, nil
	default:
		return "", "", fmt.Errorf("unsupported archive format %q: want zip, tar or targz", r.URL.Query().Get("algo"))
	}
}

func setContentDisposition(w http.ResponseWriter, r *http.Request, file *files.FileInfo) {
	if r.URL.Query().Get("inline") == "true" {
		// As per RFC6266 section 4.3
		w.Header().Set("Content-Disposition", "inline; filename*=utf-8''"+url.PathEscape(file.Name))
	} else {
		// As per RFC6266 section 4.3
		w.Header().Set("Content-Disposition", "attachment; filename*=utf-8''"+url.PathEscape(file.Name))
		w.Header().Set("Content-Type", "application/octet-stream")
	}
}

var rawHandler = withUser(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	if !d.user.Perm.Download {
		return http.StatusAccepted, nil
	}

	file, err := files.NewFileInfo(&files.FileOptions{
		Fs:         d.user.Fs,
		Path:       r.URL.Path,
		Modify:     d.user.Perm.Modify,
		Expand:     false,
		ReadHeader: d.server.TypeDetectionByHeader,
		Checker:    d,
	})
	if err != nil {
		return errToStatus(err), err
	}

	if files.IsNamedPipe(file.Mode) {
		setContentDisposition(w, r, file)
		return 0, nil
	}

	if !file.IsDir {
		return rawFileHandler(w, r, file)
	}

	return rawDirHandler(w, r, d, file)
})

// archiveEntry is one file packed into a download archive. Names are
// pre-hardened by getFiles and never escape the archive root.
type archiveEntry struct {
	info fs.FileInfo
	name string
	open func() (fs.File, error)
}

func getFiles(d *data, path, commonPath string) ([]archiveEntry, error) {
	if !d.Check(path) {
		return nil, nil
	}

	info, err := d.user.Fs.Stat(path)
	if err != nil {
		return nil, err
	}

	var archiveFiles []archiveEntry

	if path != commonPath {
		nameInArchive := strings.TrimPrefix(path, commonPath)
		nameInArchive = strings.TrimPrefix(nameInArchive, string(filepath.Separator))
		nameInArchive = filepath.ToSlash(nameInArchive)
		// A backslash is a legal filename character on POSIX hosts, so it can
		// reach here verbatim. Rewriting it to the path separator "/" would
		// manufacture a traversal sequence (e.g. "..\..\x" -> "../../x") that
		// escapes the extraction directory on the victim's machine, while
		// leaving it as "\" lets Windows extractors treat it as a separator.
		// Neutralize it to an inert character instead of turning it into one.
		nameInArchive = strings.ReplaceAll(nameInArchive, "\\", "_")

		// Defense in depth: never emit an archive entry whose path escapes the
		// archive root, regardless of how the name was produced.
		if cleaned := gopath.Clean("/" + nameInArchive); cleaned != "/"+nameInArchive {
			return nil, fmt.Errorf("refusing unsafe archive entry name: %q", nameInArchive)
		}

		archiveFiles = append(archiveFiles, archiveEntry{
			info: info,
			name: nameInArchive,
			open: func() (fs.File, error) {
				return d.user.Fs.Open(path)
			},
		})
	}

	if info.IsDir() {
		f, err := d.user.Fs.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		names, err := f.Readdirnames(0)
		if err != nil {
			return nil, err
		}

		for _, name := range names {
			fPath := filepath.Join(path, name)
			subFiles, err := getFiles(d, fPath, commonPath)
			if err != nil {
				log.Printf("Failed to get files from %s: %v", fPath, err)
				continue
			}
			archiveFiles = append(archiveFiles, subFiles...)
		}
	}

	return archiveFiles, nil
}

func rawDirHandler(w http.ResponseWriter, r *http.Request, d *data, file *files.FileInfo) (int, error) {
	filenames, err := parseQueryFiles(r, file, d.user)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	extension, format, err := parseQueryAlgorithm(r)
	if err != nil {
		return http.StatusBadRequest, err
	}

	commonDir := fileutils.CommonPrefix(filepath.Separator, filenames...)

	var allFiles []archiveEntry
	for _, fname := range filenames {
		archiveFiles, err := getFiles(d, fname, commonDir)
		if err != nil {
			log.Printf("Failed to get files from %s: %v", fname, err)
			continue
		}
		allFiles = append(allFiles, archiveFiles...)
	}

	name := filepath.Base(commonDir)
	if name == "." || name == "" || name == string(filepath.Separator) {
		if file.Name != "" {
			name = file.Name
		} else {
			actual, statErr := file.Fs.Stat(".")
			if statErr != nil {
				return http.StatusInternalServerError, statErr
			}
			name = actual.Name()
		}
	}
	if len(filenames) > 1 {
		name = "_" + name
	}
	name += extension
	w.Header().Set("Content-Disposition", "attachment; filename*=utf-8''"+url.PathEscape(name))

	if err := writeArchive(r.Context(), w, format, allFiles); err != nil {
		return http.StatusInternalServerError, err
	}

	return 0, nil
}

// writeArchive packs entries with the standard library. Directories are
// stored as explicit entries so empty ones survive the round trip.
func writeArchive(ctx context.Context, w io.Writer, format archiveFormat, files []archiveEntry) error {
	switch format {
	case archiveZip:
		zw := zip.NewWriter(w)
		defer zw.Close()
		for _, e := range files {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := writeZipEntry(zw, e); err != nil {
				return err
			}
		}
		return zw.Close()
	case archiveTarGz:
		gz := gzip.NewWriter(w)
		defer gz.Close()
		tw := tar.NewWriter(gz)
		defer tw.Close()
		for _, e := range files {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := writeTarEntry(tw, e); err != nil {
				return err
			}
		}
		if err := tw.Close(); err != nil {
			return err
		}
		return gz.Close()
	default:
		tw := tar.NewWriter(w)
		defer tw.Close()
		for _, e := range files {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := writeTarEntry(tw, e); err != nil {
				return err
			}
		}
		return tw.Close()
	}
}

func writeZipEntry(zw *zip.Writer, e archiveEntry) error {
	header, err := zip.FileInfoHeader(e.info)
	if err != nil {
		return err
	}
	header.Name = e.name
	if e.info.IsDir() {
		header.Name += "/"
		header.Method = zip.Store
		_, err := zw.CreateHeader(header)
		return err
	}
	header.Method = zip.Deflate
	out, err := zw.CreateHeader(header)
	if err != nil {
		return err
	}
	return copyEntry(out, e)
}

func writeTarEntry(tw *tar.Writer, e archiveEntry) error {
	header, err := tar.FileInfoHeader(e.info, "")
	if err != nil {
		return err
	}
	header.Name = e.name
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	if e.info.IsDir() {
		return nil
	}
	return copyEntry(tw, e)
}

func copyEntry(w io.Writer, e archiveEntry) error {
	fd, err := e.open()
	if err != nil {
		return err
	}
	defer fd.Close()
	_, err = io.Copy(w, fd)
	return err
}

func rawFileHandler(w http.ResponseWriter, r *http.Request, file *files.FileInfo) (int, error) {
	fd, err := file.Fs.Open(file.Path)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	defer fd.Close()

	setContentDisposition(w, r, file)
	w.Header().Add("Content-Security-Policy", `script-src 'none';`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "private")
	http.ServeContent(w, r, file.Name, file.ModTime, fd)
	return 0, nil
}
