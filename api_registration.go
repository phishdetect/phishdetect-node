// PhishDetect
// Copyright (c) 2018-2019 Claudio Guarnieri.
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
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func apiRegistrationPending(w http.ResponseWriter, r *http.Request) {
	if !enforceUserAuth {
		errorWithJSON(w, "The Node does not enforce user authentication", http.StatusForbidden, nil)
		return
	}

	users, err := db.GetAllUsers()
	if err != nil {
		errorWithJSON(w, "Failed to fetch the list of users", http.StatusInternalServerError, err)
		return
	}

	notActive := []User{}
	for _, user := range users {
		if user.Activated == false {
			notActive = append(notActive, user)
		}
	}

	responseWithJSON(w, notActive)
}

func apiRegistrationActivate(w http.ResponseWriter, r *http.Request) {
	if !enforceUserAuth {
		errorWithJSON(w, "The Node does not enforce user authentication", http.StatusForbidden, nil)
		return
	}

	vars := mux.Vars(r)
	apiKey := vars["apiKey"]

	err := db.ActivateUser(apiKey)
	if err != nil {
		errorWithJSON(w, "Failed to activate the user", http.StatusInternalServerError, err)
		return
	}

	response := map[string]interface{}{
		"msg": fmt.Sprintf("User with API key %s activated successfully", apiKey),
	}

	responseWithJSON(w, response)
}
