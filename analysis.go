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
	log "github.com/sirupsen/logrus"
)

func checkIfBlocklisted(target string) (phishdetect.Warning, error) {
	link, err := phishdetect.NewLink(target)
	toCheck := []string{
		encodeSHA256(strings.ToLower(strings.TrimSpace(link.Domain))),
		encodeSHA256(strings.ToLower(strings.TrimSpace(link.TopDomain))),
	}

	iocs, err := db.GetIndicators(IndicatorsLimitAll, IndicatorsStatusEnabled)
	if err != nil {
		return phishdetect.Warning{}, err
	}
	for _, ioc := range iocs {
		if phishdetect.SliceContains(toCheck, ioc.Hashed) {
			log.Debug("Target ", target, " is blocklisted by indicator with hash ", ioc.Hashed)
			return phishdetect.Warning{
				Score: 100,
				Name: "blocklisted",
				Description: fmt.Sprintf("The domain was blocklisted in PhishDetect Node by indicator with hash %s", ioc.Hashed),
			}, nil
		}
	}

	return phishdetect.Warning{}, nil
}

// analyzeDomain is used to statically analyze a domain name.
func analyzeDomain(domain string) (*AnalysisResults, error) {
	urlNormalized := phishdetect.NormalizeURL(domain)
	urlFinal := urlNormalized

	if !validateURL(urlNormalized) {
		return nil, errors.New(ErrorMsgInvalidURL)
	}

	analysis := phishdetect.NewAnalysis(urlFinal, "")
	loadBrands(*analysis)

	err := analysis.AnalyzeDomain()
	if err != nil {
		log.Error("Failed to analyze domain: ", err)
		return nil, errors.New(ErrorMsgAnalysisFailed)
	}
	brand := analysis.Brands.GetBrand()

	results := AnalysisResults{
		URL:        domain,
		URLFinal:   urlFinal,
		Safelisted: analysis.Safelisted,
		Dangerous:  analysis.Dangerous,
		Score:      analysis.Score,
		Brand:      brand,
		Warnings:   analysis.Warnings,
	}

	blocklisted, err := checkIfBlocklisted(domain)
	if err == nil && blocklisted.Score > 0 {
		results.Score += blocklisted.Score
		results.Warnings = append(results.Warnings, blocklisted)
	}

	return &results, nil
}

// analyzeURL is used to statically analyze a URL.
func analyzeURL(url string) (*AnalysisResults, error) {
	urlNormalized := phishdetect.NormalizeURL(url)
	urlFinal := urlNormalized

	if !validateURL(urlNormalized) {
		return nil, errors.New(ErrorMsgInvalidURL)
	}

	analysis := phishdetect.NewAnalysis(urlFinal, "")
	loadBrands(*analysis)

	err := analysis.AnalyzeURL()
	if err != nil {
		log.Error("Failed to analyze URL: ", err)
		return nil, errors.New(ErrorMsgAnalysisFailed)
	}
	brand := analysis.Brands.GetBrand()

	results := AnalysisResults{
		URL:        url,
		URLFinal:   urlFinal,
		Safelisted: analysis.Safelisted,
		Dangerous:  analysis.Dangerous,
		Score:      analysis.Score,
		Brand:      brand,
		Warnings:   analysis.Warnings,
	}

	blocklisted, err := checkIfBlocklisted(urlFinal)
	if err == nil && blocklisted.Score > 0 {
		results.Score += blocklisted.Score
		results.Warnings = append(results.Warnings, blocklisted)
	}

	return &results, nil
}

// analyzeLink is used to dynamically analyze a URL.
func analyzeLink(url string) (*AnalysisResults, error) {
	urlNormalized := phishdetect.NormalizeURL(url)
	urlFinal := urlNormalized

	var screenshot string

	if !validateURL(urlNormalized) {
		return nil, errors.New(ErrorMsgInvalidURL)
	}

	// Setting Docker API version.
	os.Setenv("DOCKER_API_VERSION", apiVersion)
	// Instantiate new browser and open the link.
	browser := phishdetect.NewBrowser(urlNormalized, "", false, false, "")
	err := browser.Run()
	if err != nil {
		log.Error("Failed to instantiate browser: ", err)
		return nil, errors.New(ErrorMsgAnalysisFailed)
	}
	urlFinal = browser.FinalURL

	if strings.HasPrefix(urlFinal, "chrome-error://") {
		return nil, errors.New(ErrorMsgConnectionFailed)
	}

	screenshot = fmt.Sprintf("data:image/png;base64,%s", browser.ScreenshotData)
	analysis := phishdetect.NewAnalysis(urlFinal, browser.HTML)

	loadBrands(*analysis)

	err = analysis.AnalyzeHTML()
	if err != nil {
		log.Error("Failed to analyze HTML: ", err)
		return nil, errors.New(ErrorMsgAnalysisFailed)
	}
	err = analysis.AnalyzeURL()
	if err != nil {
		log.Error("Failed to analyze URL: ", err)
		return nil, errors.New(ErrorMsgAnalysisFailed)
	}
	brand := analysis.Brands.GetBrand()

	results := AnalysisResults{
		URL:        url,
		URLFinal:   urlFinal,
		Safelisted: analysis.Safelisted,
		Dangerous:  analysis.Dangerous,
		Score:      analysis.Score,
		Brand:      brand,
		Screenshot: screenshot,
		Warnings:   analysis.Warnings,
		Visits:     browser.Visits,
		Resources:  browser.Resources,
		Dialogs:    browser.Dialogs,
		Downloads:  browser.Downloads,
		HTML:       browser.HTML,
	}

	blocklisted, err := checkIfBlocklisted(urlFinal)
	if err == nil && blocklisted.Score > 0 {
		results.Score += blocklisted.Score
		results.Warnings = append(results.Warnings, blocklisted)
	}

	return &results, nil
}

// analyzeHTML is used to statically analyze an HTML page.
func analyzeHTML(url, htmlEncoded string) (*AnalysisResults, error) {
	urlFinal := url

	if !validateURL(url) {
		return nil, errors.New(ErrorMsgInvalidURL)
	}

	if htmlEncoded == "" {
		return nil, errors.New(ErrorMsgInvalidHTML)
	}

	htmlData, err := base64.StdEncoding.DecodeString(htmlEncoded)
	if err != nil {
		return nil, errors.New(ErrorMsgInvalidHTML)
	}
	html := string(htmlData)

	analysis := phishdetect.NewAnalysis(urlFinal, html)
	loadBrands(*analysis)

	err = analysis.AnalyzeHTML()
	if err != nil {
		log.Error("Failed to analyze HTML: ", err)
		return nil, errors.New(ErrorMsgAnalysisFailed)
	}
	err = analysis.AnalyzeURL()
	if err != nil {
		log.Error("Failed to analyze URL: ", err)
		return nil, errors.New(ErrorMsgAnalysisFailed)
	}
	brand := analysis.Brands.GetBrand()

	results := AnalysisResults{
		URL:        url,
		URLFinal:   urlFinal,
		Safelisted: analysis.Safelisted,
		Dangerous:  analysis.Dangerous,
		Score:      analysis.Score,
		Brand:      brand,
		Warnings:   analysis.Warnings,
		HTML:       html,
	}

	blocklisted, err := checkIfBlocklisted(urlFinal)
	if err == nil && blocklisted.Score > 0 {
		results.Score += blocklisted.Score
		results.Warnings = append(results.Warnings, blocklisted)
	}

	return &results, nil
}
