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
