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
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"
)

type AddIndicatorsRequest struct {
	Type       string   `json:"type"`
	Indicators []string `json:"indicators"`
	Tags       []string `json:"tags"`
}

func apiIndicatorsFetch(w http.ResponseWriter, r *http.Request) {
	log.Debug("Received request to fetch indicators")

	// TODO: Move this connection elsewhere.
	db, err := NewDatabase()
	if err != nil {
		errorWithJSON(w, "Failed to connect to database", http.StatusInternalServerError, err)
		return
	}
	defer db.Close()

	// We get the indicators from the DB.
	iocs, err := db.GetIndicators()
	if err != nil {
		errorWithJSON(w, "Failed to fetch indicators from database", http.StatusInternalServerError, err)
		return
	}

	// We loop through the list of indicators and generate the response.
	var senders []string
	var domains []string
	for _, ioc := range iocs {
		switch ioc.Type{
		case "email":
			senders = append(senders, ioc.Hashed)
		case "domain":
			domains = append(domains, ioc.Hashed)
		}
	}
	// We assemble the response.
	indicators := map[string][]string{
		"senders": senders,
		"domains": domains,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(indicators)
}

func apiIndicatorsAdd(w http.ResponseWriter, r *http.Request) {
	log.Debug("Received request to add indicators")

	// We decode the request to an AddIndicatorsRequest.
	decoder := json.NewDecoder(r.Body)
	var req AddIndicatorsRequest
	err := decoder.Decode(&req)
	if err != nil {
		errorWithJSON(w, "Unable to parse request", http.StatusBadRequest, err)
		return
	}

	// TODO: We need to move this connection elsewhere.
	db, err := NewDatabase()
	if err != nil {
		errorWithJSON(w, "Failed to connect to database", http.StatusInternalServerError, err)
		return
	}
	defer db.Close()

	// We loop through the submitted indicators and try to add them to the DB.
	addedCounter := 0
	for _, ioc := range req.Indicators {
		err = db.AddIndicator(req.Type, ioc, req.Tags)
		if err != nil {
			log.Warning("Failed to add indicator to database: ", err.Error())
			continue
		}
		// If the addition was successful, we increase the counter.
		addedCounter++
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"msg": fmt.Sprintf("Added %d indicators", addedCounter)})
}
