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
	"encoding/base64"
	"net/http"
	"time"

	"github.com/botherder/go-savetime/hashes"
	pongo "github.com/flosch/pongo2"
	"github.com/gorilla/mux"
	"github.com/nu7hatch/gouuid"
	log "github.com/sirupsen/logrus"
)

func guiLinkCheck(w http.ResponseWriter, r *http.Request) {
	if !enableAnalysis {
		errorPage(w, "Analysis of links and pages was disabled by the administrator.")
		return
	}

	vars := mux.Vars(r)
	urlEncoded := vars["url"]

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

	// The url is normally send base64-encoded.
	urlDecoded := string(data)
	log.Info("Received analysis request for ", urlDecoded)

	// These options are used if the user sent an HTML page from the
	// browser extension.
	html := ""
	screenshot := ""
	if r.Method == "POST" {
		r.ParseForm()
		// We get the base64 encoded HTML page.
		html = r.PostFormValue("html")
		// We are gonna display the screenshot sent by the browser.
		screenshot = r.PostFormValue("screenshot")
	}

	tpl, err := tmplSet.FromCache("link.html")
	err = tpl.ExecuteWriter(pongo.Context{
		"url":        urlDecoded,
		"html":       html,
		"screenshot": screenshot,
		"key":        getAPIKeyFromRequest(r),
	}, w)
	if err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func guiLinkAnalyze(w http.ResponseWriter, r *http.Request) {
	if !enableAnalysis {
		errorMessage(w, "Analysis of links and pages was disabled by the administrator.")
		return
	}

	r.ParseForm()
	url := r.PostFormValue("url")
	urlSHA1, _ := hashes.StringSHA1(url)
	htmlEncoded := r.PostFormValue("html")
	screenshot := r.PostFormValue("screenshot")

	// For the moment, finalURL will be the original URL.
	finalURL := url

	var alertType string
	var results *AnalysisResults
	var err error

	// If there is no specified HTML string, it means we need to open the link.
	if htmlEncoded == "" {
		alertType = "analysis_link"
		results, err = analyzeURLDynamic(url)
		if err != nil {
			errorMessage(w, err.Error())
			return
		}

		finalURL = results.FinalURL
		screenshot = results.Screenshot
	} else {
		alertType = "analysis_html"
		results, err = analyzeHTML(url, htmlEncoded)
		if err != nil {
			errorMessage(w, err.Error())
			return
		}
	}

	log.Info("Completed analysis of ", url)

	// If the site is safelisted, or the final score is low, we offer
	// to continue to the original link.
	if (results.Safelisted || results.Score < 30) && !results.Dangerous {
		finalURLEncoded := base64.StdEncoding.EncodeToString([]byte(finalURL))
		tpl, err := tmplSet.FromCache("continue.html")
		err = tpl.ExecuteWriter(pongo.Context{
			"url":             url,
			"finalURLEncoded": finalURLEncoded,
			"finalURL":        finalURL,
			"sha1":            urlSHA1,
			"brand":           results.Brand,
			"safelisted":      results.Safelisted,
			"screenshot":      screenshot,
			"key":             getAPIKeyFromRequest(r),
		}, w)
		if err != nil {
			log.Error(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// At this point we return or the function will continue.
		return
	}

	// We store a record in the database.
	uuidInstance, _ := uuid.NewV4()
	uuidString := uuidInstance.String()
	alert := Alert{
		Type:        alertType,
		Match:       url,
		Indicator:   "",
		UserContact: "",
		Datetime:    time.Now().UTC(),
		UUID:        uuidString,
	}
	err = db.AddAlert(alert)
	if err != nil {
		log.Error(err)
	}

	results.AlertUUID = uuidString
	err = db.AddAnalysisResults(*results)
	if err != nil {
		log.Error(err)
	}

	tpl, err := tmplSet.FromCache("warning.html")
	err = tpl.ExecuteWriter(pongo.Context{
		"url":        url,
		"finalURL":   finalURL,
		"sha1":       urlSHA1,
		"warnings":   results.Warnings,
		"brand":      results.Brand,
		"score":      results.Score,
		"screenshot": screenshot,
		"safelisted": results.Safelisted,
		"dangerous":  results.Dangerous,
	}, w)
	if err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
