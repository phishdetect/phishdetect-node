// PhishDetect
// Copyright (c) 2018-2020 Claudio Guarnieri.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const (
	roleUser      = "user"
	roleSubmitter = "submitter"
	roleAdmin     = "admin"
)

var rolesRank = map[string]int{
	roleUser:      0,
	roleSubmitter: 1,
	roleAdmin:     2,
}

func generateAPIKey(source string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(source), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return encodeSHA1(string(hash)), nil
}

func getAPIKeyFromRequest(r *http.Request) string {
	keys, ok := r.URL.Query()["key"]
	if !ok || len(keys) < 1 {
		if r.Method == "POST" {
			r.ParseForm()
			return r.PostFormValue("key")
		} else {
			return ""
		}
	}

	key := strings.ToLower(keys[0])
	if !sha1RegexCompiled.MatchString(key) {
		return ""
	}

	return key
}

func authMiddleware(next http.HandlerFunc, requiredRole string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If there is no role specified, the API is not protected.
		if enforceUserAuth == false || requiredRole == "" {
			next(w, r)
			return
		}

		// Try to fetch an API key.
		apiKey := getAPIKeyFromRequest(r)
		if apiKey == "" {
			errorWithJSON(w, ERROR_MSG_INVALID_API_KEY, http.StatusUnauthorized, nil)
			return
		}

		// Look for a user with this API key.
		user, err := db.GetUserByKey(apiKey)
		if err != nil {
			// The user does not exist with that API key.
			errorWithJSON(w, ERROR_MSG_NOT_AUTHORIZED, http.StatusUnauthorized, nil)
			return
		}

		// If we didn't find a user for this API key and there is
		// enforceUserAuth enabled, then we return a 401 because no API
		// should be publicly accessible.
		if !user.Activated && enforceUserAuth == true {
			errorWithJSON(w, ERROR_MSG_USER_NOT_ACTIVATED, http.StatusUnauthorized, nil)
			return
		}

		// Which minimum role is necessary for this route?
		if requiredRole == roleUser {
			// At this point all these statements should be true:
			// 1. The request comes from a valid user (regardless of the role).
			// 2. The requested resource requires a valid user.
			// 3. Whether enforceUserAuth is true or false should be irrelevant.
			next(w, r)
			return
		} else if rolesRank[requiredRole] >= rolesRank[roleSubmitter] {
			// In case of other roles (submitter and admin) we check if the
			// matched has a role value >= the required role value.
			if rolesRank[user.Role] >= rolesRank[requiredRole] {
				next(w, r)
				return
			} else {
				// Otherwise we return 401.
				errorWithJSON(w, ERROR_MSG_NOT_AUTHORIZED, http.StatusUnauthorized, nil)
				return
			}
		}

		errorWithJSON(w, ERROR_MSG_UNEXPECTED_ERROR, http.StatusInternalServerError, nil)
	})
}

func apiAuth(w http.ResponseWriter, r *http.Request) {
	// This is just a dummy request used to test users.
	responseWithJSON(w, map[string]string{})
}
