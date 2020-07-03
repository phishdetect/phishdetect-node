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
	"strings"
	"time"

	"github.com/manifoldco/promptui"
	log "github.com/sirupsen/logrus"
	"gopkg.in/go-playground/validator.v9"
)

func checkIfUserExists(email string) (bool, error) {
	// Check if a user already exists with the specified email address.
	existingUsers, err := db.GetAllUsers()
	if err != nil {
		return false, err
	}
	for _, existingUser := range existingUsers {
		if strings.ToLower(existingUser.Email) == strings.ToLower(email) {
			return true, nil
		}
	}
	return false, nil
}

func createNewUser() {
	log.Info("Creating a new user")

	promptRole := promptui.Select{
		Label: "Role",
		Items: []string{roleAdmin, roleSubmitter, roleUser},
	}
	_, role, err := promptRole.Run()
	if err != nil {
		log.Error("Failed to enter role: ", err)
		return
	}
	log.Info("You chose role: ", role)

	promptName := promptui.Prompt{
		Label: "Name",
	}
	name, err := promptName.Run()
	if err != nil {
		log.Error("Failed to enter name: ", err)
		return
	}
	log.Info("You chose name: ", name)

	promptEmail := promptui.Prompt{
		Label: "Email",
	}
	email, err := promptEmail.Run()
	if err != nil {
		log.Error("Failed to enter email: ", err)
		return
	}
	log.Info("You chose email: ", email)

	exists, _ := checkIfUserExists(email)
	if exists == true {
		log.Error("User with provided email account already exists")
		return
	}

	apiKey, err := generateAPIKey(email)
	if err != nil {
		log.Error("Something went wrong while generating your API key! Please try again.")
		return
	}

	user := User{
		Name:      name,
		Email:     email,
		Key:       apiKey,
		Role:      role,
		Activated: true,
		Datetime:  time.Now().UTC(),
	}

	// Validate if the user provided proper data.
	validate = validator.New()
	err = validate.Struct(user)
	if err != nil {
		log.Error("You did not provide a valid name and/or email address")
		return
	}

	// Add user to the database.
	err = db.AddUser(user)
	if err != nil {
		log.Error("Failed to register user: ", err)
		return
	}

	log.Info("New user \"", name, "\" created with API key: ", apiKey)
}
