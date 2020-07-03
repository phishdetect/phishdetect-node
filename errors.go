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

const (
	ErrorMsgNotAuthorized         = "You are not authorized to perform this operation"
	ErrorMsgUserNotActivated      = "Your user has not been activated by the administrators"
	ErrorMsgInvalidAPIKey         = "Your secret token is invalid"
	ErrorMsgUnexpectedError       = "Some unexpected error occurred"
	ErrorMsgAnalysisDisabled      = "Analysis was disabled by administrator"
	ErrorMsgInvalidRequest        = "Invalid request"
	ErrorMsgInvalidURL            = "Invalid URL"
	ErrorMsgAnalysisFailed        = "Something failed during the analysis"
	ErrorMsgInvalidHTML           = "Invalid HTML"
	ErrorMsgIndicatorsFetchFailed = "Failed to fetch indicators from database"
	ErrorMsgParseRequestFailed    = "Unable to parse request"
	ErrorMsgNoAuthRequired        = "The Node does not enforce user authentication"
	ErrorMsgConnectionFailed      = "An error occurred while visiting the link: the website might be offline"
)
