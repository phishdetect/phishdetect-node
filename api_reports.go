// PhishDetect
// Copyright (c) 2018-2021 Claudio Guarnieri.
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

	"github.com/gorilla/mux"
	"github.com/nu7hatch/gouuid"
)

func apiReportsFetch(w http.ResponseWriter, r *http.Request) {
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

	var reportType string = ""
	keys, ok = r.URL.Query()["type"]
	if ok && len(keys) == 1 {
		reportType = keys[0]
	}

	reports, err := db.GetAllReports(offset, limit, reportType)
	if err != nil {
		errorWithJSON(w, "Failed to fetch reports from database", http.StatusInternalServerError, err)
		return
	}

	responseWithJSON(w, reports)
}

func apiReportsAdd(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var report Report
	err := decoder.Decode(&report)
	if err != nil {
		errorWithJSON(w, "Unable to parse report", http.StatusBadRequest, err)
		return
	}

	report.Datetime = time.Now().UTC()

	uuidInstance, _ := uuid.NewV4()
	report.UUID = uuidInstance.String()

	key := getAPIKeyFromRequest(r)
	user, _ := db.GetUserByKey(key)
	report.User = user.UUID

	err = db.AddReport(report)
	if err != nil {
		errorWithJSON(w, "Unable to store report in database", http.StatusInternalServerError, err)
		return
	}

	response := map[string]string{
		"msg":  "Report message added successfully",
		"uuid": report.UUID,
	}

	responseWithJSON(w, response)
}

func apiReportsDetails(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	report, err := db.GetReportByUUID(vars["uuid"])
	if err != nil {
		errorWithJSON(w, "Failed to fetch report from database", http.StatusInternalServerError, err)
		return
	}

	responseWithJSON(w, report)
}
