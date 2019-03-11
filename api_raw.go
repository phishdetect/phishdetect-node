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
	"encoding/json"
	"net/http"
	"time"

	"github.com/nu7hatch/gouuid"
)

func apiRawAdd(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var raw Raw
	err := decoder.Decode(&raw)
	if err != nil {
		errorWithJSON(w, "Unable to parse raw message", http.StatusBadRequest, err)
		return
	}

	raw.Datetime = time.Now().UTC()

	u4, _ := uuid.NewV4()
	raw.UUID = u4.String()

	err = db.AddRaw(raw)
	if err != nil {
		errorWithJSON(w, "Unable to store raw message in database", http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"msg": "Raw message added successfully", "uuid": raw.UUID})
}
