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

// import (
// 	"net/http"

// 	pongo "github.com/flosch/pongo2"
// 	"github.com/gorilla/mux"
// 	log "github.com/sirupsen/logrus"
// )

// func guiEmail(w http.ResponseWriter, r *http.Request) {
// 	vars := mux.Vars(r)
// 	uuid := vars["uuid"]

// 	raw, err := db.GetRawByUUID(uuid)
// 	if err != nil {
// 		errorPage(w, "You didn't specify a valid email")
// 		return
// 	}

// 	err = tmplEmail.ExecuteWriter(pongo.Context{
// 		"content": raw.Content,
// 		"uuid":    raw.UUID,
// 	}, w)
// 	if err != nil {
// 		log.Error(err)
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 	}
// }
