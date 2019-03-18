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
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

type RequestAddIndicators struct {
	Type       string   `json:"type"`
	Indicators []string `json:"indicators"`
	Tags       []string `json:"tags"`
	Key        string   `json:"key"`
}

type RequestIndicatorsDetails struct {
	Indicator string `json:"indicator"`
	Key       string `json:"key"`
}

func apiIndicatorsFetch(w http.ResponseWriter, r *http.Request) {
	// We get the indicators from the DB.
	iocs, err := db.GetAllIndicators()
	if err != nil {
		errorWithJSON(w, "Failed to fetch indicators from database", http.StatusInternalServerError, err)
		return
	}

	// We loop through the list of indicators and generate the response.
	emails := []string{}
	domains := []string{}
	for _, ioc := range iocs {
		switch ioc.Type {
		case "email":
			emails = append(emails, ioc.Hashed)
		case "domain":
			domains = append(domains, ioc.Hashed)
		}
	}
	// We assemble the response.
	indicators := map[string][]string{
		"emails":  emails,
		"domains": domains,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(indicators)
}

func apiIndicatorsAdd(w http.ResponseWriter, r *http.Request) {
	// We decode the request to an RequestAddIndicators.
	decoder := json.NewDecoder(r.Body)
	var req RequestAddIndicators
	err := decoder.Decode(&req)
	if err != nil {
		errorWithJSON(w, "Unable to parse request", http.StatusBadRequest, err)
		return
	}

	user := getUserFromKey(req.Key)
	if user == nil {
		errorWithJSON(w, "You are not authorized to perform this operation", http.StatusUnauthorized, nil)
		return
	}

	// We loop through the submitted indicators and try to add them to the DB.
	addedCounter := 0
	for _, indicator := range req.Indicators {
		var hashed string
		// Check if we received an already hashed IOC.
		if validateSHA256(indicator) {
			// If we do, the indicator is already the hashed version.
			hashed = indicator
			// And the original indicator value shall be blank.
			indicator = ""
		} else {
			// Otherwise, we first clean the indicator...
			indicator = cleanIndicator(indicator)
			// ... then we hash the original indicator.
			hashed = encodeSHA256(indicator)
		}

		ioc := Indicator{
			Type:     req.Type,
			Original: indicator,
			Hashed:   hashed,
			Tags:     req.Tags,
			Datetime: time.Now().UTC(),
			Owner:    user.Name,
		}

		err = db.AddIndicator(ioc)
		if err != nil {
			log.Warning("Failed to add indicator to database: ", err.Error())
			continue
		}
		// If the addition was successful, we increase the counter.
		addedCounter++
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"msg": fmt.Sprintf("Added %d indicators", addedCounter), "counter": addedCounter})
}

func apiIndicatorsDetails(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var req RequestIndicatorsDetails
	err := decoder.Decode(&req)
	if err != nil {
		errorWithJSON(w, "Unable to parse request", http.StatusBadRequest, err)
		return
	}

	user := getUserFromKey(req.Key)
	if user == nil {
		errorWithJSON(w, "You are not authorized to perform this operation", http.StatusUnauthorized, nil)
		return
	}

	ioc, err := db.GetIndicatorByHash(req.Indicator)
	if err != nil {
		errorWithJSON(w, "Failed to fetch indicator from database", http.StatusInternalServerError, err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ioc)
}
