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

type RequestRawFetch struct {
	Key string `json:"key"`
}

type RequestRawDetails struct {
	Key  string `json:"key"`
	UUID string `json:"uuid"`
}

func apiRawFetch(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var req RequestRawFetch
	err := decoder.Decode(&req)
	if err != nil {
		errorWithJSON(w, "Unable to parse request", http.StatusBadRequest, err)
		return
	}

	user := getUserFromKey(req.Key)
	if user == nil || user.Role != "admin" {
		errorWithJSON(w, "You are not authorized to perform this operation", http.StatusUnauthorized, nil)
		return
	}

	rawMessages, err := db.GetAllRaw()
	if err != nil {
		errorWithJSON(w, "Failed to fetch raw messages from database", http.StatusInternalServerError, err)
		return
	}

	responseWithJSON(w, rawMessages)
}

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

	response := map[string]string{
		"msg":  "Raw message added successfully",
		"uuid": raw.UUID,
	}

	responseWithJSON(w, response)
}

func apiRawDetails(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var req RequestRawDetails
	err := decoder.Decode(&req)
	if err != nil {
		errorWithJSON(w, "Unable to parse request", http.StatusBadRequest, err)
		return
	}

	user := getUserFromKey(req.Key)
	if user == nil || user.Role != "admin" {
		errorWithJSON(w, "You are not authorized to perform this operation", http.StatusUnauthorized, nil)
		return
	}

	raw, err := db.GetRawByUUID(req.UUID)
	if err != nil {
		errorWithJSON(w, "Failed to fetch raw message from database", http.StatusInternalServerError, err)
		return
	}

	responseWithJSON(w, raw)
}
