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
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/nu7hatch/gouuid"
)

func apiAlertsFetch(w http.ResponseWriter, r *http.Request) {
	var offset int64 = 0
	keys, ok := r.URL.Query()["offset"]
	if ok && len(keys) == 1 {
		offset, _ = strconv.ParseInt(keys[0], 10, 64)
	}

	var limit int64 = 0
	keys, ok = r.URL.Query()["limit"]
	if ok && len(keys) == 1 {
		limit, _ = strconv.ParseInt(keys[0], 10, 64)
	}

	alerts, err := db.GetAllAlerts(offset, limit)
	if err != nil {
		errorWithJSON(w, "Failed to fetch alerts from database", http.StatusInternalServerError, err)
		return
	}

	responseWithJSON(w, alerts)
}

func apiAlertsAdd(w http.ResponseWriter, r *http.Request) {
	// We decode the request to an Alert.
	decoder := json.NewDecoder(r.Body)
	var alert Alert
	err := decoder.Decode(&alert)
	if err != nil {
		errorWithJSON(w, "Unable to parse alert", http.StatusBadRequest, err)
		return
	}

	alert.Datetime = time.Now().UTC()

	uuidInstance, _ := uuid.NewV4()
	alert.UUID = uuidInstance.String()

	key := getAPIKeyFromRequest(r)
	user, _ := db.GetUserByKey(key)
	alert.User = user.UUID

	err = db.AddAlert(alert)
	if err != nil {
		errorWithJSON(w, "Unable to store alert in database", http.StatusInternalServerError, err)
		return
	}

	response := map[string]string{
		"msg":  "Alert added successfully",
		"uuid": alert.UUID,
	}

	responseWithJSON(w, response)
}
