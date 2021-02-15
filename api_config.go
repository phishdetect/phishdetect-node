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
	"net/http"
)

// Config contains information on the configuration of the node.
type Config struct {
	EnableAPI             bool   `json:"enable_api"`
	EnableGUI             bool   `json:"enable_gui"`
	EnableAnalysis        bool   `json:"enable_analysis"`
	EnforceUserAuth       bool   `json:"enforce_user_auth"`
	AdministatorName      string `json:"admin_name"`
	AdministratorContacts string `json:"admin_contacts"`
}

func apiConfig(w http.ResponseWriter, r *http.Request) {
	cfg := Config{
		EnableAPI:             enableAPI,
		EnableGUI:             enableGUI,
		EnableAnalysis:        enableAnalysis,
		EnforceUserAuth:       enforceUserAuth,
		AdministatorName:      flagAdminName,
		AdministratorContacts: flagAdminContacts,
	}

	responseWithJSON(w, cfg)
}
