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
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	pongo "github.com/flosch/pongo2"
	"github.com/gorilla/mux"
	"github.com/nu7hatch/gouuid"
	"github.com/phishdetect/phishdetect"
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
	urlSHA1 := encodeSHA1(url)
	htmlEncoded := r.PostFormValue("html")
	screenshot := r.PostFormValue("screenshot")

	html := ""

	// For the moment, urlFinal will be the original URL.
	urlFinal := url
	urlNormalized := phishdetect.NormalizeURL(url)

	// If there is no specified HTML string, it means we need to open the link.
	if htmlEncoded == "" {
		if !validateURL(url) {
			errorMessage(w, "You have submitted an invalid link.")
			return
		}

		// Setting Docker API version.
		os.Setenv("DOCKER_API_VERSION", apiVersion)
		// Instantiate new browser and open the link.
		browser := phishdetect.NewBrowser(urlNormalized, "", false, "")
		err := browser.Run()
		if err != nil {
			log.Error(err)
			errorMessage(w, "Something failed while trying to launch the containerized browser. The URL might be invalid.")
			return
		}
		html = browser.HTML
		urlFinal = browser.FinalURL
		screenshot = fmt.Sprintf("data:image/png;base64,%s", browser.ScreenshotData)
		// Otherwise, we decode the base64-encoded HTML string and use that.
	} else {
		data, err := base64.StdEncoding.DecodeString(htmlEncoded)
		if err != nil {
			log.Error(err)
			errorMessage(w, "I received invalid HTML data. I expect a base64 encoded string.")
			return
		}
		html = string(data)
	}

	// Check for Chrome errors, generally raised by connection failures.
	if strings.HasPrefix(urlFinal, "chrome-error://") {
		errorMessage(w, "An error occurred while visiting the link. The website might be offline.")
		return
	}

	// Now that we have URL and HTML we can analyze results.
	analysis := phishdetect.NewAnalysis(urlFinal, html)
	loadBrands(*analysis)

	err := analysis.AnalyzeHTML()
	if err != nil {
		errorMessage(w, err.Error())
		return
	}
	err = analysis.AnalyzeURL()
	if err != nil {
		errorMessage(w, err.Error())
		return
	}
	brand := analysis.Brands.GetBrand()

	log.Info("Completed analysis of ", url)

	// If the site is safelisted, or the final score is low, we offer the
	// redirect to the original link.
	if analysis.Safelisted || analysis.Score < 30 {
		tpl, err := tmplSet.FromCache("redirect.html")
		err = tpl.ExecuteWriter(pongo.Context{
			"url":           url,
			"urlNormalized": urlNormalized,
			"urlFinal":      urlFinal,
			"sha1":          urlSHA1,
			"brand":         brand,
			"safelisted":    analysis.Safelisted,
			"screenshot":    screenshot,
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
	u4, _ := uuid.NewV4()
	event := Event{
		Type:        "analysis",
		Match:       url,
		Indicator:   "",
		UserContact: "",
		Datetime:    time.Now().UTC(),
		UUID:        u4.String(),
	}
	err = db.AddEvent(event)
	if err != nil {
		log.Error(err)
	}

	// Otherwise we show the warning.
	tpl, err := tmplSet.FromCache("warning.html")
	err = tpl.ExecuteWriter(pongo.Context{
		"url":           url,
		"urlNormalized": urlNormalized,
		"urlFinal":      urlFinal,
		"sha1":          urlSHA1,
		"warnings":      analysis.Warnings,
		"brand":         brand,
		"score":         analysis.Score,
		"screenshot":    screenshot,
	}, w)
	if err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
