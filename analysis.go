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
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/botherder/go-savetime/hashes"
	"github.com/botherder/go-savetime/slice"
	"github.com/phishdetect/phishdetect"
	"github.com/phishdetect/phishdetect/browser"
	"github.com/phishdetect/phishdetect/link"
	"github.com/phishdetect/phishdetect/utils"
	log "github.com/sirupsen/logrus"
)

func checkIfBlocklisted(target string) (phishdetect.Warning, error) {
	link, err := link.New(target)
	domainHash, _ := hashes.StringSHA256(strings.ToLower(strings.TrimSpace(link.Domain)))
	topDomainHash, _ := hashes.StringSHA256(strings.ToLower(strings.TrimSpace(link.TopDomain)))
	targetHashes := []string{domainHash, topDomainHash}

	iocs, err := db.GetIndicators(IndicatorsLimitAll, IndicatorsStatusEnabled)
	if err != nil {
		return phishdetect.Warning{}, err
	}
	for _, ioc := range iocs {
		if slice.ContainsNoCase(targetHashes, ioc.Hashed) {
			log.Debug("Target ", target, " is blocklisted by indicator with hash ", ioc.Hashed)
			return phishdetect.Warning{
				Score:       100,
				Name:        "blocklisted",
				Description: fmt.Sprintf("The domain was blocklisted in PhishDetect Node by indicator with hash %s", ioc.Hashed),
			}, nil
		}
	}

	return phishdetect.Warning{}, nil
}

// analyzeDomain is used to statically analyze a domain name.
func analyzeDomain(domain string) (*AnalysisResults, error) {
	urlNormalized := utils.NormalizeURL(domain)
	finalURL := urlNormalized

	if !validateURL(urlNormalized) {
		return nil, errors.New(ErrorMsgInvalidURL)
	}

	a := phishdetect.NewAnalysis(finalURL, "")
	customBrands.LoadBrands(*a)

	err := a.AnalyzeDomain()
	if err != nil {
		log.Error("Failed to analyze domain: ", err)
		return nil, errors.New(ErrorMsgAnalysisFailed)
	}
	brand := a.Brands.GetBrand()

	results := AnalysisResults{
		URL:        domain,
		FinalURL:   finalURL,
		Safelisted: a.Safelisted,
		Dangerous:  a.Dangerous,
		Score:      a.Score,
		Brand:      brand,
		Warnings:   a.Warnings,
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
	urlNormalized := utils.NormalizeURL(url)
	finalURL := urlNormalized

	if !validateURL(urlNormalized) {
		return nil, errors.New(ErrorMsgInvalidURL)
	}

	a := phishdetect.NewAnalysis(finalURL, "")
	customBrands.LoadBrands(*a)

	err := a.AnalyzeURL()
	if err != nil {
		log.Error("Failed to analyze URL: ", err)
		return nil, errors.New(ErrorMsgAnalysisFailed)
	}
	brand := a.Brands.GetBrand()

	results := AnalysisResults{
		URL:        url,
		FinalURL:   finalURL,
		Safelisted: a.Safelisted,
		Dangerous:  a.Dangerous,
		Score:      a.Score,
		Brand:      brand,
		Warnings:   a.Warnings,
	}

	blocklisted, err := checkIfBlocklisted(finalURL)
	if err == nil && blocklisted.Score > 0 {
		results.Score += blocklisted.Score
		results.Warnings = append(results.Warnings, blocklisted)
	}

	return &results, nil
}

// analyzeHTML is used to statically analyze an HTML page.
func analyzeHTML(url, htmlEncoded string) (*AnalysisResults, error) {
	finalURL := url

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

	a := phishdetect.NewAnalysis(finalURL, html)
	customBrands.LoadBrands(*a)

	err = a.AnalyzeHTML()
	if err != nil {
		log.Error("Failed to analyze HTML: ", err)
		return nil, errors.New(ErrorMsgAnalysisFailed)
	}
	err = a.AnalyzeURL()
	if err != nil {
		log.Error("Failed to analyze URL: ", err)
		return nil, errors.New(ErrorMsgAnalysisFailed)
	}
	brand := a.Brands.GetBrand()

	htmlSHA256, _ := hashes.StringSHA256(html)
	results := AnalysisResults{
		URL:        url,
		FinalURL:   finalURL,
		Safelisted: a.Safelisted,
		Dangerous:  a.Dangerous,
		Score:      a.Score,
		Brand:      brand,
		Warnings:   a.Warnings,
		HTML:       html,
		HTMLSHA256: htmlSHA256,
	}

	blocklisted, err := checkIfBlocklisted(finalURL)
	if err == nil && blocklisted.Score > 0 {
		results.Score += blocklisted.Score
		results.Warnings = append(results.Warnings, blocklisted)
	}

	return &results, nil
}

// analyzeURLDynamic is used to dynamically analyze a URL.
func analyzeURLDynamic(url string) (*AnalysisResults, error) {
	urlNormalized := utils.NormalizeURL(url)
	finalURL := urlNormalized

	var screenshot string

	if !validateURL(urlNormalized) {
		return nil, errors.New(ErrorMsgInvalidURL)
	}

	// Setting Docker API version.
	os.Setenv("DOCKER_API_VERSION", flagDockerAPIVersion)
	// Instantiate new browser and open the link.
	b := browser.New(urlNormalized, "", "", false, "")
	err := b.Run()
	if err != nil {
		log.Error("Failed to instantiate browser: ", err)
		return nil, errors.New(ErrorMsgAnalysisFailed)
	}
	finalURL = b.FinalURL

	screenshot = fmt.Sprintf("data:image/png;base64,%s", b.ScreenshotData)
	a := phishdetect.NewAnalysis(finalURL, b.HTML)

	customBrands.LoadBrands(*a)

	err = a.AnalyzeBrowserResults(b)
	if err != nil {
		log.Error("Failed to analyze HTML: ", err)
		return nil, errors.New(ErrorMsgAnalysisFailed)
	}
	err = a.AnalyzeURL()
	if err != nil {
		log.Error("Failed to analyze URL: ", err)
		return nil, errors.New(ErrorMsgAnalysisFailed)
	}
	brand := a.Brands.GetBrand()

	results := AnalysisResults{
		URL:               url,
		FinalURL:          finalURL,
		Safelisted:        a.Safelisted,
		Dangerous:         a.Dangerous,
		Score:             a.Score,
		Brand:             brand,
		Screenshot:        screenshot,
		Warnings:          a.Warnings,
		Visits:            b.Visits,
		NavigationHistory: b.NavigationHistory,
		ResourcesData:     b.ResourcesData,
		Dialogs:           b.Dialogs,
		Downloads:         b.Downloads,
		HTML:              b.HTML,
		HTMLSHA256:        b.HTMLSHA256,
	}

	blocklisted, err := checkIfBlocklisted(finalURL)
	if err == nil && blocklisted.Score > 0 {
		results.Score += blocklisted.Score
		results.Warnings = append(results.Warnings, blocklisted)
	}

	return &results, nil
}
