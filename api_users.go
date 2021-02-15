// PhishDetect
// Copyright (c) 2018-2021 Claudio Guarnieri.
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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/nu7hatch/gouuid"
	"gopkg.in/go-playground/validator.v9"
)

func apiUsersRegister(w http.ResponseWriter, r *http.Request) {
	if !enforceUserAuth {
		errorWithJSON(w, ErrorMsgNoAuthRequired, http.StatusBadRequest, nil)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var user User
	err := decoder.Decode(&user)
	if err != nil {
		errorWithJSON(w, "You did not provide a valid registration request", http.StatusBadRequest, err)
		return
	}

	user.Email = strings.ToLower(user.Email)

	// Validate if the user provided proper data.
	validate := validator.New()
	err = validate.Struct(user)
	if err != nil {
		errorWithJSON(w, "You did not provide a valid name and/or email address",
			http.StatusBadRequest, nil)
		return
	}

	exists, _ := checkIfUserExists(user.Email)
	if exists == true {
		errorWithJSON(w, "A user already registered with the same email address",
			http.StatusForbidden, nil)
		return
	}

	apiKey, err := generateAPIKey(user.Email)
	if err != nil {
		errorWithJSON(w, "Something went wrong while generating your API key! Please try again.",
			http.StatusInternalServerError, err)
		return
	}

	uuidInstance, _ := uuid.NewV4()
	user.UUID = uuidInstance.String()
	user.Key = apiKey
	user.Role = roleUser
	user.Activated = false
	user.Datetime = time.Now().UTC()

	// Add user to the database.
	err = db.AddUser(user)
	if err != nil {
		errorWithJSON(w, "Failed to store new user in database",
			http.StatusInternalServerError, err)
		return
	}

	response := map[string]interface{}{
		"msg":       "User registered successfully",
		"activated": user.Activated,
		"key":       user.Key,
	}

	responseWithJSON(w, response)
}

func apiUsersPending(w http.ResponseWriter, r *http.Request) {
	if !enforceUserAuth {
		errorWithJSON(w, ErrorMsgNoAuthRequired, http.StatusForbidden, nil)
		return
	}

	users, err := db.GetAllUsers()
	if err != nil {
		errorWithJSON(w, "Failed to fetch the list of users",
			http.StatusInternalServerError, err)
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

func apiUsersActive(w http.ResponseWriter, r *http.Request) {
	users, err := db.GetAllUsers()
	if err != nil {
		errorWithJSON(w, "Failed to fetch the list of users",
			http.StatusInternalServerError, err)
		return
	}

	usersOnly := []User{}
	for _, user := range users {
		if user.Role == "user" && user.Activated == true {
			usersOnly = append(usersOnly, user)
		}
	}

	responseWithJSON(w, usersOnly)
}

func apiUsersActivate(w http.ResponseWriter, r *http.Request) {
	if !enforceUserAuth {
		errorWithJSON(w, ErrorMsgNoAuthRequired, http.StatusForbidden, nil)
		return
	}

	vars := mux.Vars(r)
	uuid := vars["uuid"]

	err := db.ActivateUser(uuid)
	if err != nil {
		errorWithJSON(w, "Failed to activate the user",
			http.StatusInternalServerError, err)
		return
	}

	response := map[string]interface{}{
		"msg": fmt.Sprintf("User with UUID %s activated successfully", uuid),
	}

	responseWithJSON(w, response)
}

func apiUsersDeactivate(w http.ResponseWriter, r *http.Request) {
	if !enforceUserAuth {
		errorWithJSON(w, ErrorMsgNoAuthRequired, http.StatusForbidden, nil)
		return
	}

	vars := mux.Vars(r)
	uuid := vars["uuid"]

	err := db.DeactivateUser(uuid)
	if err != nil {
		errorWithJSON(w, "Failed to deactivate the user",
			http.StatusInternalServerError, err)
		return
	}

	response := map[string]interface{}{
		"msg": fmt.Sprintf("User with UUID %s deactivated successfully", uuid),
	}

	responseWithJSON(w, response)
}
