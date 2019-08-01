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
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/phishdetect/phishdetect"
)

// AnalysisRequest contains the information required to start an analysis.
type AnalysisRequest struct {
	URL  string `json:"url"`
	HTML string `json:"html"`
}

// AnalysisResults contains all the information we want to return through the
// apiAnalyze API.
type AnalysisResults struct {
	URL        string   `json:"url"`
	URLFinal   string   `json:"url_final"`
	Safelisted bool     `json:"safelisted"`
	Brand      string   `json:"brand"`
	Score      int      `json:"score"`
	Screenshot string   `json:"screenshot"`
	Warnings   []string `json:"warnings"`
}

func apiAnalyzeDomain(w http.ResponseWriter, r *http.Request) {
	if disableAnalysis == true {
		errorWithJSON(w, "Analysis was disabled by administrator", http.StatusForbidden, nil)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var req AnalysisRequest
	err := decoder.Decode(&req)
	if err != nil {
		errorWithJSON(w, "Invalid request", http.StatusBadRequest, err)
		return
	}

	urlNormalized := phishdetect.NormalizeURL(req.URL)
	urlFinal := urlNormalized

	if !validateURL(urlNormalized) {
		errorWithJSON(w, "Invalid URL", http.StatusBadRequest, nil)
		return
	}

	analysis := phishdetect.NewAnalysis(urlFinal, "")
	loadBrands(*analysis)

	err = analysis.AnalyzeDomain()
	if err != nil {
		errorWithJSON(w, "Something failed during the analysis", http.StatusInternalServerError, err)
		return
	}
	brand := analysis.Brands.GetBrand()

	var warnings []string
	for _, warning := range analysis.Warnings {
		warnings = append(warnings, warning.Description)
	}

	results := AnalysisResults{
		URL:        req.URL,
		URLFinal:   urlFinal,
		Safelisted: analysis.Safelisted,
		Score:      analysis.Score,
		Brand:      brand,
		Screenshot: "",
		Warnings:   warnings,
	}

	responseWithJSON(w, results)
}

func apiAnalyzeLink(w http.ResponseWriter, r *http.Request) {
	if disableAnalysis == true {
		errorWithJSON(w, "Analysis was disabled by administrator", http.StatusForbidden, nil)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var req AnalysisRequest
	err := decoder.Decode(&req)
	if err != nil {
		errorWithJSON(w, "Invalid request", http.StatusBadRequest, err)
		return
	}

	urlNormalized := phishdetect.NormalizeURL(req.URL)
	urlFinal := urlNormalized

	var html string
	var screenshot string

	if !validateURL(urlNormalized) {
		errorWithJSON(w, "Invalid URL", http.StatusBadRequest, nil)
		return
	}

	// Setting Docker API version.
	os.Setenv("DOCKER_API_VERSION", apiVersion)
	// Instantiate new browser and open the link.
	browser := phishdetect.NewBrowser(urlNormalized, "", false, "")
	err = browser.Run()
	if err != nil {
		errorWithJSON(w, "Something failed during the analysis", http.StatusInternalServerError, err)
		return
	}
	html = browser.HTML
	urlFinal = browser.FinalURL
	screenshot = fmt.Sprintf("data:image/png;base64,%s", browser.ScreenshotData)

	analysis := phishdetect.NewAnalysis(urlFinal, html)
	loadBrands(*analysis)

	err = analysis.AnalyzeHTML()
	if err != nil {
		errorWithJSON(w, "Something failed during the analysis", http.StatusInternalServerError, err)
		return
	}
	err = analysis.AnalyzeURL()
	if err != nil {
		errorWithJSON(w, "Something failed during the analysis", http.StatusInternalServerError, err)
		return
	}
	brand := analysis.Brands.GetBrand()

	var warnings []string
	for _, warning := range analysis.Warnings {
		warnings = append(warnings, warning.Description)
	}

	results := AnalysisResults{
		URL:        req.URL,
		URLFinal:   urlFinal,
		Safelisted: analysis.Safelisted,
		Score:      analysis.Score,
		Brand:      brand,
		Screenshot: screenshot,
		Warnings:   warnings,
	}

	responseWithJSON(w, results)
}

func apiAnalyzeHTML(w http.ResponseWriter, r *http.Request) {
	if disableAnalysis == true {
		errorWithJSON(w, "Analysis was disabled by administrator", http.StatusForbidden, nil)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var req AnalysisRequest
	err := decoder.Decode(&req)
	if err != nil {
		errorWithJSON(w, "Invalid request", http.StatusBadRequest, err)
		return
	}

	url := req.URL
	urlFinal := url

	if !validateURL(url) {
		errorWithJSON(w, "Invalid URL", http.StatusBadRequest, nil)
		return
	}

	if req.HTML == "" {
		errorWithJSON(w, "Invalid HTML", http.StatusBadRequest, nil)
		return
	}

	htmlData, err := base64.StdEncoding.DecodeString(req.HTML)
	if err != nil {
		errorWithJSON(w, "Invalid HTML", http.StatusBadRequest, nil)
		return
	}
	html := string(htmlData)

	analysis := phishdetect.NewAnalysis(urlFinal, html)
	loadBrands(*analysis)

	err = analysis.AnalyzeHTML()
	if err != nil {
		errorWithJSON(w, "Something failed during the analysis", http.StatusInternalServerError, err)
		return
	}
	err = analysis.AnalyzeURL()
	if err != nil {
		errorWithJSON(w, "Something failed during the analysis", http.StatusInternalServerError, err)
		return
	}
	brand := analysis.Brands.GetBrand()

	var warnings []string
	for _, warning := range analysis.Warnings {
		warnings = append(warnings, warning.Description)
	}

	results := AnalysisResults{
		URL:        url,
		URLFinal:   urlFinal,
		Safelisted: analysis.Safelisted,
		Score:      analysis.Score,
		Brand:      brand,
		Screenshot: "",
		Warnings:   warnings,
	}

	responseWithJSON(w, results)
}
