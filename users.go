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
	"fmt"
	"strings"
	"time"

	"github.com/manifoldco/promptui"
	"github.com/nu7hatch/gouuid"
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
	fmt.Println("Creating a new user")

	promptRole := promptui.Select{
		Label: "Role",
		Items: []string{roleAdmin, roleSubmitter, roleUser},
	}
	_, role, err := promptRole.Run()
	if err != nil {
		fmt.Println("Failed to enter role:", err.Error())
		return
	}
	fmt.Println("You picked role:", role)

	promptName := promptui.Prompt{
		Label: "Name",
	}
	name, err := promptName.Run()
	if err != nil {
		fmt.Println("Failed to enter name:", err.Error())
		return
	}
	fmt.Println("You chose name:", name)

	promptEmail := promptui.Prompt{
		Label: "Email",
	}
	email, err := promptEmail.Run()
	if err != nil {
		fmt.Println("Failed to enter email:", err.Error())
		return
	}
	fmt.Println("You chose email:", email)

	exists, _ := checkIfUserExists(email)
	if exists == true {
		fmt.Println("User with provided email account already exists")
		return
	}

	apiKey, err := generateAPIKey(email)
	if err != nil {
		fmt.Println("Something went wrong while generating your API key! Please try again.")
		return
	}

	uuidInstance, _ := uuid.NewV4()
	user := User{
		UUID:      uuidInstance.String(),
		Name:      name,
		Email:     email,
		Key:       apiKey,
		Role:      role,
		Activated: true,
		Datetime:  time.Now().UTC(),
	}

	// Validate if the user provided proper data.
	validate := validator.New()
	err = validate.Struct(user)
	if err != nil {
		fmt.Println("You did not provide a valid name and/or email address")
		return
	}

	// Add user to the database.
	err = db.AddUser(user)
	if err != nil {
		fmt.Println("Failed to register user:", err.Error())
		return
	}

	fmt.Println("New user \"", name, "\" created with API key:", apiKey)
}
