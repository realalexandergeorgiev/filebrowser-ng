package fbhttp

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/realalexandergeorgiev/filebrowser-ng/auth"
	fberrors "github.com/realalexandergeorgiev/filebrowser-ng/errors"
	"github.com/realalexandergeorgiev/filebrowser-ng/users"
)

var (
	NonModifiableFieldsForNonAdmin = []string{"Username", "Scope", "LockPassword", "Perm", "Commands", "Rules"}
)

type modifyUserRequest struct {
	modifyRequest
	Data *users.User `json:"data"`
}

func getUserID(r *http.Request) (uint, error) {
	i, err := strconv.ParseUint(r.PathValue("id"), 10, 0)
	if err != nil {
		return 0, err
	}
	return uint(i), err
}

// userUpdateRevokesSessions reports whether updating the given (Title-cased,
// possibly empty for full updates) fields must invalidate the target user's
// login sessions. Purely cosmetic profile fields keep sessions alive;
// identity, credential, permission, scope and rules changes do not.
func userUpdateRevokesSessions(which []string) bool {
	if len(which) == 0 {
		return true
	}
	for _, field := range which {
		switch strings.ToLower(field) {
		case "locale", "viewmode", "singleclick", "redirectaftercopymove",
			"sorting", "hidedotfiles", "dateformat", "aceeditortheme":
			continue
		default:
			return true
		}
	}
	return false
}

func getUser(_ http.ResponseWriter, r *http.Request) (*modifyUserRequest, error) {
	if r.Body == nil {
		return nil, fberrors.ErrEmptyRequest
	}

	req := &modifyUserRequest{}
	err := json.NewDecoder(r.Body).Decode(req)
	if err != nil {
		return nil, err
	}

	if req.What != "user" {
		return nil, fberrors.ErrInvalidDataType
	}

	return req, nil
}

func withSelfOrAdmin(fn handleFunc) handleFunc {
	return withUser(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		id, err := getUserID(r)
		if err != nil {
			return http.StatusInternalServerError, err
		}

		if d.user.ID != id && !d.user.Perm.Admin {
			return http.StatusForbidden, nil
		}

		d.raw = id
		return fn(w, r, d)
	})
}

var usersGetHandler = withAdmin(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	users, err := d.store.Users.Gets(d.server.Root, d.server.FollowExternalSymlinks)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	for _, u := range users {
		u.Password = ""
	}

	sort.Slice(users, func(i, j int) bool {
		return users[i].ID < users[j].ID
	})

	return renderJSON(w, r, users)
})

var userGetHandler = withSelfOrAdmin(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	u, err := d.store.Users.Get(d.server.Root, d.server.FollowExternalSymlinks, d.raw.(uint))
	if errors.Is(err, fberrors.ErrNotExist) {
		return http.StatusNotFound, err
	}

	if err != nil {
		return http.StatusInternalServerError, err
	}

	u.Password = ""
	if !d.user.Perm.Admin {
		u.Scope = ""
	}
	return renderJSON(w, r, u)
})

var userDeleteHandler = withSelfOrAdmin(func(_ http.ResponseWriter, r *http.Request, d *data) (int, error) {
	if r.Body == nil {
		return http.StatusBadRequest, fberrors.ErrEmptyRequest
	}

	var body struct {
		CurrentPassword string `json:"current_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return http.StatusBadRequest, err
	}

	if d.settings.AuthMethod == auth.MethodJSONAuth {
		if !users.CheckPwd(body.CurrentPassword, d.user.Password) {
			return http.StatusBadRequest, fberrors.ErrCurrentPasswordIncorrect
		}
	}

	err := d.store.Users.Delete(d.raw.(uint))
	if err != nil {
		return errToStatus(err), err
	}

	// A deleted user must lose access at once, not at token expiry.
	if err := d.store.Sessions.RevokeUser(d.raw.(uint)); err != nil {
		log.Printf("delete user: failed to revoke sessions: %v", err)
	}

	return http.StatusOK, nil
})

var userPostHandler = withAdmin(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	req, err := getUser(w, r)
	if err != nil {
		return http.StatusBadRequest, err
	}

	if d.settings.AuthMethod == auth.MethodJSONAuth {
		if !users.CheckPwd(req.CurrentPassword, d.user.Password) {
			return http.StatusBadRequest, fberrors.ErrCurrentPasswordIncorrect
		}
	}

	if len(req.Which) != 0 {
		return http.StatusBadRequest, nil
	}

	if req.Data.Password == "" {
		return http.StatusBadRequest, fberrors.ErrEmptyPassword
	}

	req.Data.Password, err = users.ValidateAndHashPwd(req.Data.Password, d.settings.MinimumPasswordLength)
	if err != nil {
		return http.StatusBadRequest, err
	}

	if req.Data.Perm.Share && !req.Data.Perm.Download {
		return http.StatusBadRequest, fberrors.ErrShareRequiresDownload
	}

	userHome, err := d.settings.MakeUserDir(req.Data.Username, req.Data.Scope, d.server.Root)
	if err != nil {
		log.Printf("create user: failed to mkdir user home dir: [%s]", userHome)
		return http.StatusInternalServerError, err
	}
	req.Data.Scope = userHome
	log.Printf("user: %s, home dir: [%s].", req.Data.Username, userHome)

	err = d.store.Users.Save(req.Data)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	w.Header().Set("Location", "/settings/users/"+strconv.FormatUint(uint64(req.Data.ID), 10))
	return http.StatusCreated, nil
})

var userPutHandler = withSelfOrAdmin(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	req, err := getUser(w, r)
	if err != nil {
		return http.StatusBadRequest, err
	}

	if d.settings.AuthMethod == auth.MethodJSONAuth {
		var sensibleFields = map[string]struct{}{
			"all":          {},
			"username":     {},
			"password":     {},
			"scope":        {},
			"lockPassword": {},
			"commands":     {},
			"perm":         {},
		}

		for _, field := range req.Which {
			if _, ok := sensibleFields[strings.ToLower(field)]; ok {
				if !users.CheckPwd(req.CurrentPassword, d.user.Password) {
					return http.StatusBadRequest, fberrors.ErrCurrentPasswordIncorrect
				}
				break
			}
		}
	}

	if req.Data.ID != d.raw.(uint) {
		return http.StatusBadRequest, nil
	}

	for _, field := range req.Which {
		if strings.ToLower(field) == "perm" || strings.ToLower(field) == "all" {
			if req.Data.Perm.Share && !req.Data.Perm.Download {
				return http.StatusBadRequest, fberrors.ErrShareRequiresDownload
			}
		}
	}

	if len(req.Which) == 0 || (len(req.Which) == 1 && req.Which[0] == "all") {
		if !d.user.Perm.Admin {
			return http.StatusForbidden, nil
		}

		if req.Data.Password != "" {
			req.Data.Password, err = users.ValidateAndHashPwd(req.Data.Password, d.settings.MinimumPasswordLength)
			if err != nil {
				return http.StatusBadRequest, err
			}
		} else {
			var suser *users.User
			suser, err = d.store.Users.Get(d.server.Root, d.server.FollowExternalSymlinks, d.raw.(uint))
			if err != nil {
				return http.StatusInternalServerError, err
			}
			req.Data.Password = suser.Password
		}

		req.Which = []string{}
	}

	for k, v := range req.Which {
		v = cases.Title(language.English, cases.NoLower).String(v)
		req.Which[k] = v

		if v == "Password" {
			if !d.user.Perm.Admin && d.user.LockPassword {
				return http.StatusForbidden, nil
			}

			req.Data.Password, err = users.ValidateAndHashPwd(req.Data.Password, d.settings.MinimumPasswordLength)
			if err != nil {
				return http.StatusBadRequest, err
			}
		}

		for _, f := range NonModifiableFieldsForNonAdmin {
			if !d.user.Perm.Admin && v == f {
				return http.StatusForbidden, nil
			}
		}
	}

	err = d.store.Users.Update(req.Data, req.Which...)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	// Password, permission, scope and identity changes must invalidate
	// outstanding tokens at once; purely cosmetic profile fields do not.
	if userUpdateRevokesSessions(req.Which) {
		if err := d.store.Sessions.RevokeUser(d.raw.(uint)); err != nil {
			log.Printf("update user: failed to revoke sessions: %v", err)
		}
	}

	return http.StatusOK, nil
})
