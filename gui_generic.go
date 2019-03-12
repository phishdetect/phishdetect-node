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
	"net/http"

	log "github.com/sirupsen/logrus"
)

func guiIndex(w http.ResponseWriter, r *http.Request) {
	err := tmplIndex.ExecuteWriter(nil, w)
	if err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func guiCheck(w http.ResponseWriter, r *http.Request) {
	err := tmplCheck.ExecuteWriter(nil, w)
	if err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
