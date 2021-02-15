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
	"time"

	"github.com/nu7hatch/gouuid"
)

func apiReviewsAdd(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var review Review
	err := decoder.Decode(&review)
	if err != nil {
		errorWithJSON(w, "Unable to parse review", http.StatusBadRequest, err)
		return
	}

	_, err = db.GetIndicatorByHash(review.Indicator)
	if err != nil {
		errorWithJSON(w, "Unable to find the indicator you requested to be reviewed",
			http.StatusBadRequest, err)
		return
	}

	review.Datetime = time.Now().UTC()

	uuidInstance, _ := uuid.NewV4()
	review.UUID = uuidInstance.String()

	key := getAPIKeyFromRequest(r)
	user, _ := db.GetUserByKey(key)
	review.User = user.UUID

	err = db.AddReview(review)
	if err != nil {
		errorPage(w, "Unable to store review request in database")
		return
	}

	response := map[string]string{
		"msg":  "Review request submitted successfully",
		"uuid": review.UUID,
	}

	responseWithJSON(w, response)
}
