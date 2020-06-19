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
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/phishdetect/phishdetect"
)

func analyzeDomain(domain string) (*AnalysisResults, error) {
	urlNormalized := phishdetect.NormalizeURL(domain)
	urlFinal := urlNormalized

	if !validateURL(urlNormalized) {
		return nil, errors.New(ERROR_MSG_INVALID_URL)
	}

	analysis := phishdetect.NewAnalysis(urlFinal, "")
	loadBrands(*analysis)

	err := analysis.AnalyzeDomain()
	if err != nil {
		return nil, errors.New(ERROR_MSG_ANALYSIS_FAILED)
	}
	brand := analysis.Brands.GetBrand()

	results := AnalysisResults{
		URL:        domain,
		URLFinal:   urlFinal,
		Safelisted: analysis.Safelisted,
		Score:      analysis.Score,
		Brand:      brand,
		Warnings:   analysis.Warnings,
	}

	return &results, nil
}

func analyzeURL(url string) (*AnalysisResults, error) {
	urlNormalized := phishdetect.NormalizeURL(url)
	urlFinal := urlNormalized

	var screenshot string

	if !validateURL(urlNormalized) {
		return nil, errors.New(ERROR_MSG_INVALID_URL)
	}

	// Setting Docker API version.
	os.Setenv("DOCKER_API_VERSION", apiVersion)
	// Instantiate new browser and open the link.
	browser := phishdetect.NewBrowser(urlNormalized, "", false, "")
	err := browser.Run()
	if err != nil {
		return nil, errors.New(ERROR_MSG_ANALYSIS_FAILED)
	}
	urlFinal = browser.FinalURL

	if strings.HasPrefix(urlFinal, "chrome-error://") {
		return nil, errors.New(ERROR_MSG_CONNECTION_FAILED)
	}

	screenshot = fmt.Sprintf("data:image/png;base64,%s", browser.ScreenshotData)
	analysis := phishdetect.NewAnalysis(urlFinal, browser.HTML)

	loadBrands(*analysis)

	err = analysis.AnalyzeHTML()
	if err != nil {
		return nil, errors.New(ERROR_MSG_ANALYSIS_FAILED)
	}
	err = analysis.AnalyzeURL()
	if err != nil {
		return nil, errors.New(ERROR_MSG_ANALYSIS_FAILED)
	}
	brand := analysis.Brands.GetBrand()

	results := AnalysisResults{
		URL:        url,
		URLFinal:   urlFinal,
		Safelisted: analysis.Safelisted,
		Score:      analysis.Score,
		Brand:      brand,
		Screenshot: screenshot,
		Warnings:   analysis.Warnings,
		Visits:     browser.Visits,
		Resources:  browser.Resources,
		HTML:       browser.HTML,
	}

	return &results, nil
}

func analyzeHTML(url, htmlEncoded string) (*AnalysisResults, error) {
	urlFinal := url

	if !validateURL(url) {
		return nil, errors.New(ERROR_MSG_INVALID_URL)
	}

	if htmlEncoded == "" {
		return nil, errors.New(ERROR_MSG_INVALID_HTML)
	}

	htmlData, err := base64.StdEncoding.DecodeString(htmlEncoded)
	if err != nil {
		return nil, errors.New(ERROR_MSG_INVALID_HTML)
	}
	html := string(htmlData)

	analysis := phishdetect.NewAnalysis(urlFinal, html)
	loadBrands(*analysis)

	err = analysis.AnalyzeHTML()
	if err != nil {
		return nil, errors.New(ERROR_MSG_ANALYSIS_FAILED)
	}
	err = analysis.AnalyzeURL()
	if err != nil {
		return nil, errors.New(ERROR_MSG_ANALYSIS_FAILED)
	}
	brand := analysis.Brands.GetBrand()

	results := AnalysisResults{
		URL:        url,
		URLFinal:   urlFinal,
		Safelisted: analysis.Safelisted,
		Score:      analysis.Score,
		Brand:      brand,
		Warnings:   analysis.Warnings,
		HTML:       html,
	}

	return &results, nil
}
