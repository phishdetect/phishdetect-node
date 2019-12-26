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
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	pongo "github.com/flosch/pongo2"
	"github.com/gorilla/mux"
	"github.com/nu7hatch/gouuid"
	"github.com/phishdetect/phishdetect"
	log "github.com/sirupsen/logrus"
)

func guiReport(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	urlEncoded := strings.TrimSpace(vars["url"])

	// If no url was specified, we give an error.
	if urlEncoded == "" {
		errorPage(w, "You didn't specify a valid URL")
		return
	}

	data, err := base64.StdEncoding.DecodeString(urlEncoded)
	if err != nil {
		log.Error(err)
		errorPage(w, "You submitted an invalid URL argument. I expect a base64 encoded URL.")
		return
	}

	urlDecoded := string(data)

	_, err = phishdetect.NewLink(urlDecoded)
	if err != nil {
		log.Error(err)
		errorPage(w, "The URL you reported does not seem valid.")
		return
	}

	u4, _ := uuid.NewV4()

	report := Report{
		Type:     "url",
		Content:  urlDecoded,
		Datetime: time.Now().UTC(),
		UUID:     u4.String(),
	}

	err = db.AddReport(report)
	if err != nil {
		errorPage(w, "Unable to store report in database")
		return
	}

	tpl, err := tmplSet.FromCache("report.html")
	err = tpl.ExecuteWriter(pongo.Context{
		"url": urlDecoded,
	}, w)
	if err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
