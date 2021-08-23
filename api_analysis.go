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

	"github.com/rs/zerolog/log"
)

// AnalysisRequest contains the information required to start an analysis.
type AnalysisRequest struct {
	URL  string `json:"url"`
	HTML string `json:"html"`
}

func apiAnalyzeDomain(w http.ResponseWriter, r *http.Request) {
	if !enableAnalysis {
		errorWithJSON(w, ErrorMsgAnalysisDisabled, http.StatusForbidden, nil)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var req AnalysisRequest
	err := decoder.Decode(&req)
	if err != nil {
		errorWithJSON(w, ErrorMsgInvalidRequest, http.StatusBadRequest, err)
		return
	}

	log.Debug().Str("url", req.URL).Msg("Received request to analyze domain")

	results, err := analyzeDomain(req.URL)
	if err != nil {
		errorWithJSON(w, err.Error(), http.StatusInternalServerError, err)
		return
	}

	log.Debug().Str("url", req.URL).Msg("Analysis of domain completed")

	responseWithJSON(w, results)
}

func apiAnalyzeURL(w http.ResponseWriter, r *http.Request) {
	if !enableAnalysis {
		errorWithJSON(w, ErrorMsgAnalysisDisabled, http.StatusForbidden, nil)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var req AnalysisRequest
	err := decoder.Decode(&req)
	if err != nil {
		errorWithJSON(w, ErrorMsgInvalidRequest, http.StatusBadRequest, err)
		return
	}

	log.Debug().Str("url", req.URL).Msg("Received request to analyze URL")

	results, err := analyzeURL(req.URL)
	if err != nil {
		errorWithJSON(w, err.Error(), http.StatusInternalServerError, err)
		return
	}

	log.Debug().Str("url", req.URL).Msg("Analysis of URL completed")

	responseWithJSON(w, results)
}

func apiAnalyzeHTML(w http.ResponseWriter, r *http.Request) {
	if !enableAnalysis {
		errorWithJSON(w, ErrorMsgAnalysisDisabled, http.StatusForbidden, nil)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var req AnalysisRequest
	err := decoder.Decode(&req)
	if err != nil {
		errorWithJSON(w, ErrorMsgInvalidRequest, http.StatusBadRequest, err)
		return
	}

	log.Debug().Str("url", req.URL).Msg("Received request to analyze HTML")

	results, err := analyzeHTML(req.URL, req.HTML)
	if err != nil {
		errorWithJSON(w, err.Error(), http.StatusInternalServerError, err)
		return
	}

	log.Debug().Str("url", req.URL).Msg("Analysis of HTML completed")

	responseWithJSON(w, results)
}

func apiAnalyzeLink(w http.ResponseWriter, r *http.Request) {
	if !enableAnalysis {
		errorWithJSON(w, ErrorMsgAnalysisDisabled, http.StatusForbidden, nil)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var req AnalysisRequest
	err := decoder.Decode(&req)
	if err != nil {
		errorWithJSON(w, ErrorMsgInvalidRequest, http.StatusBadRequest, err)
		return
	}

	log.Debug().Str("url", req.URL).Msg("Received request to dynamically analyze URL")

	results, err := analyzeURLDynamic(req.URL)
	if err != nil {
		errorWithJSON(w, err.Error(), http.StatusInternalServerError, err)
		return
	}

	log.Debug().Str("url", req.URL).Msg("Dynamic analysis of URL completed")

	responseWithJSON(w, results)
}
