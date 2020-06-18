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
	ERROR_MSG_NOT_AUTHORIZED          = "You are not authorized to perform this operation"
	ERROR_MSG_USER_NOT_ACTIVATED      = "Your user has not been activated by the administrators"
	ERROR_MSG_INVALID_API_KEY         = "Your secret token is invalid"
	ERROR_MSG_UNEXPECTED_ERROR        = "Some unexpected error occurred"
	ERROR_MSG_ANALYSIS_DISABLED       = "Analysis was disabled by administrator"
	ERROR_MSG_INVALID_REQUEST         = "Invalid request"
	ERROR_MSG_INVALID_URL             = "Invalid URL"
	ERROR_MSG_ANALYSIS_FAILED         = "Something failed during the analysis"
	ERROR_MSG_INVALID_HTML            = "Invalid HTML"
	ERROR_MSG_INDICATORS_FETCH_FAILED = "Failed to fetch indicators from database"
	ERROR_MSG_PARSE_REQUEST_FAILED    = "Unable to parse request"
	ERROR_MSG_NO_AUTH_REQUIRED        = "The Node does not enforce user authentication"
	ERROR_MSG_CONNECTION_FAILED       = "An error occurred while visiting the link: the website might be offline"
)
