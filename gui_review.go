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
	"time"

	pongo "github.com/flosch/pongo2"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

func guiReview(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ioc := vars["ioc"]

	indicator, err := db.GetIndicatorByHash(ioc)
	if err != nil {
		errorPage(w, "Unable to find the indicator you requested to be reviewed")
		return
	}

	review := Review{
		Indicator: ioc,
		Datetime:  time.Now().UTC(),
	}

	err = db.AddReview(review)
	if err != nil {
		errorPage(w, "Unable to store review request in database")
		return
	}

	err = tmplReview.ExecuteWriter(pongo.Context{
		"original": indicator.Original,
	}, w)
	if err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
