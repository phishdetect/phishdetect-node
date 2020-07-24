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
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/phishdetect/phishdetect"
)

func validateURL(url string) bool {
	linkTest, err := phishdetect.NewLink(url)
	if err != nil {
		return false
	}

	if linkTest.Scheme != "" && linkTest.Scheme != "http" && linkTest.Scheme != "https" {
		return false
	}

	return true
}

func encodeSHA1(target string) string {
	h := sha1.New()
	h.Write([]byte(target))
	return hex.EncodeToString(h.Sum(nil))
}

func encodeSHA256(target string) string {
	h := sha256.New()
	h.Write([]byte(target))
	return hex.EncodeToString(h.Sum(nil))
}

func validateSHA256(target string) bool {
	rxp := regexp.MustCompile(`[a-fA-F0-9]{64}`)
	return rxp.MatchString(target)
}

func cleanIndicator(indicator string) string {
	indicator = strings.TrimSpace(indicator)
	indicator = strings.ToLower(indicator)
	indicator = strings.Replace(indicator, "[@]", "@", -1)
	indicator = strings.Replace(indicator, "[.]", ".", -1)
	indicator = strings.Replace(indicator, "\\@", "@", -1)
	indicator = strings.Replace(indicator, "\\.", ".", -1)

	if !strings.Contains(indicator, "@") && strings.HasPrefix(indicator, "www.") {
		indicator = indicator[4:]
	}

	return indicator
}
