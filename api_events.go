// PhishDetect
// Copyright (C) 2018  Claudio Guarnieri
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

type FetchEventsRequest struct {
	Key string `json:"key"`
}

func apiEventsFetch(w http.ResponseWriter, r *http.Request) {
	// We decode the request to an Event.
	decoder := json.NewDecoder(r.Body)
	var req FetchEventsRequest
	err := decoder.Decode(&req)
	if err != nil {
		errorWithJSON(w, "Unable to parse event", http.StatusBadRequest, err)
		return
	}

	// First we check if the user is allowed to fetch the events.
	user := getUserFromKey(req.Key)
	if user == nil {
		errorWithJSON(w, "You are not authorized to perform this operation", http.StatusUnauthorized, nil)
		return
	}

	events, err := db.GetEvents()
	if err != nil {
		errorWithJSON(w, "Failed to fetch events from database", http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

func apiEventsAdd(w http.ResponseWriter, r *http.Request) {
	// We decode the request to an Event.
	decoder := json.NewDecoder(r.Body)
	var event Event
	err := decoder.Decode(&event)
	if err != nil {
		errorWithJSON(w, "Unable to parse event", http.StatusBadRequest, err)
		return
	}

	event.Datetime = time.Now().UTC()

	u4, _ := uuid.NewV4()
	event.UUID = u4.String()

	err = db.AddEvent(event)
	if err != nil {
		errorWithJSON(w, "Unable to store event in database", http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"msg": "Event added successfully"})
}
