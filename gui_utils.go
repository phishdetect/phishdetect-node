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

	pongo "github.com/flosch/pongo2"
	log "github.com/sirupsen/logrus"
)

func errorMessage(w http.ResponseWriter, message string) {
	tpl, err := tmplSet.FromCache("error.html")
	err = tpl.ExecuteWriter(pongo.Context{
		"message": message,
	}, w)
	if err != nil {
		log.Error(err)
		http.Error(w, "Some unexpected error occurred! :-(", http.StatusInternalServerError)
	}
	return
}

func errorPage(w http.ResponseWriter, message string) {
	tpl, err := tmplSet.FromCache("errorPage.html")
	err = tpl.ExecuteWriter(pongo.Context{
		"message": message,
	}, w)
	if err != nil {
		log.Error(err)
		http.Error(w, "Some unexpected error occurred! :-(", http.StatusInternalServerError)
	}
	return
}
