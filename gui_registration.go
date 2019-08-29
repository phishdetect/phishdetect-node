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
	"strings"
	"time"

	pongo "github.com/flosch/pongo2"
	log "github.com/sirupsen/logrus"
	"gopkg.in/go-playground/validator.v9"
)

var validate *validator.Validate

func guiRegister(w http.ResponseWriter, r *http.Request) {
	if !enforceUserAuth {
		errorPage(w, "User authentication was disabled by the administrator.")
		return
	}

	// If we receive a GET request, we show the form.
	if r.Method == "GET" {
		tpl, err := tmplSet.FromCache("register.html")
		err = tpl.ExecuteWriter(nil, w)
		if err != nil {
			log.Error(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// If we get here, we must be in a POST request.
	r.ParseForm()
	name := r.PostFormValue("name")
	email := strings.ToLower(r.PostFormValue("email"))

	// Check if a user already exists with the specified email address.
	existingUsers, err := db.GetAllUsers()
	if err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	for _, existingUser := range existingUsers {
		if strings.ToLower(existingUser.Email) == email {
			errorPage(w, "A user was already registered with the same email address!")
			return
		}
	}

	apiKey, err := generateAPIKey(email)
	if err != nil {
		errorPage(w, "Something went wrong while generating your API key! Please try again.")
		return
	}

	user := User{
		Name:      name,
		Email:     email,
		Key:       apiKey,
		Role:      roleUser,
		Activated: false,
		Datetime:  time.Now().UTC(),
	}

	// Validate if the user provided proper data.
	validate = validator.New()
	err = validate.Struct(user)
	if err != nil {
		errorPage(w, "You did not provide valid name and email address")
		return
	}

	// Add user to the database.
	err = db.AddUser(user)
	if err != nil {
		errorPage(w, fmt.Sprintf("Failed to register user: %s", err.Error()))
		return
	}

	tpl, err := tmplSet.FromCache("registerComplete.html")
	err = tpl.ExecuteWriter(pongo.Context{"key": apiKey}, w)
	if err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
