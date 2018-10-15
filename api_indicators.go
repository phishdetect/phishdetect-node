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

	indicators := map[string][]string{
		"senders": []string{"0AD6FDDB0A6CDE372FD895DB5E1B97B1EF986BE414C6890C5D7089EE80399B1E"},
		"domains": []string{"5D977F4D473900F405E5319857534A57F2D4F00630029949B458FB149F08069C"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(indicators)
}

func apiIndicatorsAdd(w http.ResponseWriter, r *http.Request) {
	log.Debug("Received request to add indicators")

	decoder := json.NewDecoder(r.Body)
	var req AddIndicatorsRequest
	err := decoder.Decode(&req)
	if err != nil {
		http.Error(w, "Unable to parse request to add indicator", http.StatusInternalServerError)
	}

	db, err := NewDatabase()
	if err != nil {
		log.Error("Failed to connect to database:", err.Error())
		http.Error(w, "Failed to connect to database", http.StatusInternalServerError)
	}
	defer db.Close()

	addedCounter := 0
	for _, ioc := range req.Indicators {
		log.Debug("Processing indicator", ioc)
		err = db.AddIndicator(req.Type, ioc, req.Tags)
		if err != nil {
			log.Warning("Failed to add indicator to database: ", err.Error())
		} else {
			addedCounter++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"msg": fmt.Sprintf("Added %d indicators", addedCounter)})
}
