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
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/botherder/go-savetime/watch"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	flag "github.com/spf13/pflag"

	"github.com/phishdetect/phishdetect"
)

const (
	regexUUID   = "[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[4|5|6|7|8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}"
	regexSHA1   = "[a-fA-F0-9]{40}"
	regexSHA256 = "[a-fA-F0-9]{64}"
)

var (
	flagCreateNewUser bool

	flagDebug            bool
	flagHost             string
	flagPortNumber       int
	flagMongoURL         string
	flagDockerAPIVersion string
	flagSafeBrowsing     string
	flagBrandsPath       string
	flagYaraPath         string
	flagAdminName        string
	flagAdminContacts    string

	enableAnalysis  bool
	enforceUserAuth bool

	db *Database

	regexSHA1Compiled *regexp.Regexp

	customBrands CustomBrands
)

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remote := r.Header.Get("X-Forwarded-For")
		if remote == "" {
			remote = r.RemoteAddr
		}
		log.Debug().Str("ip_address", remote).Str("method", r.Method).Str("uri", r.RequestURI)
		next.ServeHTTP(w, r)
	})
}

func init() {
	// Enable debug logging.
	flag.BoolVar(&flagDebug, "debug", false, "Enable debug logging")

	// With this flag, instead of starting the server, we create a new user.
	flag.BoolVar(&flagCreateNewUser, "create-user", false, "Create a new user")

	// Disable default functionality.
	flagDisableAnalysis := flag.Bool("disable-analysis", false, "Disable the ability to analyze links and pages")
	flagDisableUserAuth := flag.Bool("disable-user-auth", false, "Disable requirement of a valid user API key for all operations")

	// Server connection details.
	flag.StringVar(&flagHost, "host", "127.0.0.1", "Specify the host to bind the service on")
	flag.IntVar(&flagPortNumber, "port", 7856, "Specify which port number to bind the service on")
	flag.StringVar(&flagMongoURL, "mongo", "mongodb://localhost:27017", "Specify the mongodb url")

	// Docker API version.
	// TODO: I should look into deprecating this.
	flag.StringVar(&flagDockerAPIVersion, "api-version", "1.37", "Specify which Docker API version to use")

	// Following are optional configuration values.
	// Path to additional brands YAML definitions.
	flag.StringVar(&flagBrandsPath, "brands", "", "Specify a folder containing YAML files with Brand specifications")
	// Path to Yara rules.
	flag.StringVar(&flagYaraPath, "yara", "", "Specify a path to a file or folder contaning Yara rules")
	// Path to a file containing a Google Safebrowsing key.
	flag.StringVar(&flagSafeBrowsing, "safebrowsing", "", "Specify a file path containing your Google SafeBrowsing API key (default disabled)")
	// Name of the node or of the administrators.
	flag.StringVar(&flagAdminName, "name", "", "Specify a name to the Node or identifying the administrators")
	// URL to a page providing contact details for the Node operators.
	flag.StringVar(&flagAdminContacts, "contacts", "", "Specify a link to information or contacts details to be provided to your users")
	flag.Parse()

	// Initialize configuration values.
	enableAnalysis = !*flagDisableAnalysis
	enforceUserAuth = !*flagDisableUserAuth
}

func initDatabase() error {
	var err error
	db, err = NewDatabase(flagMongoURL)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %v", err)
	}
	return nil
}

func initLogging() {
	if flagDebug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
}

func initServer() error {
	log.Info().Bool("value", enableAnalysis).Msg("Enable analysis")
	log.Info().Bool("value", enforceUserAuth).Msg("Enforce user auth")

	// Initialize SafeBrowsing if an API key was provided.
	if flagSafeBrowsing != "" {
		if _, err := os.Stat(flagSafeBrowsing); err == nil {
			buf, _ := ioutil.ReadFile(flagSafeBrowsing)
			key := string(buf)
			if key != "" {
				phishdetect.AddSafeBrowsingKey(key)
			}
		} else {
			log.Warn().Msg("The specified Google SafeBrowsing API key file does not exist: check disabled")
		}
	}

	// Initialize Yara scanner if rule files were specified.
	if flagYaraPath != "" {
		// We do a first compilation of the Yara rules.
		err := phishdetect.LoadYaraRules(flagYaraPath)
		if err != nil {
			log.Error().Err(err).Msg("Failed to initialize Yara scanner")
		}
		// Then we set up a fsnotify watcher in order to auto-reload Yara
		// rules in case one is created, modified, or removed.
		go watch.WatchFolder(flagYaraPath, func() {
			phishdetect.LoadYaraRules(flagYaraPath)
		})
	}

	// Load custom brands.
	if flagBrandsPath != "" {
		customBrands.Path = flagBrandsPath
		// We do a first compilation of the brand definitions.
		err := customBrands.CompileBrands()
		if err != nil {
			log.Error().Err(err).Msg("Failed to compile brands")
		}
		// Then we setup a fsnofity watcher in order to auto-reload brand
		// definitions in case one is created, modified or removed.
		go watch.WatchFolder(customBrands.Path, func() {
			customBrands.CompileBrands()
		})
	}

	// Compile sha1 regex (used for key validation).
	regexSHA1Compiled = regexp.MustCompile(regexSHA1)

	return nil
}

func startServer() {
	router := mux.NewRouter()
	router.StrictSlash(true)
	router.Use(loggingMiddleware)

	// Non-auth routes.
	router.HandleFunc("/api/config/", apiConfig).Methods("GET")
	router.HandleFunc("/api/users/register/", apiUsersRegister).Methods("POST")

	// User routes.
	router.HandleFunc("/api/auth/", authMiddleware(apiAuth, roleUser)).Methods("GET")
	//--------------------------------------------------
	router.HandleFunc("/api/analyze/domain/",
		authMiddleware(apiAnalyzeDomain, roleUser)).Methods("POST")
	router.HandleFunc("/api/analyze/url/",
		authMiddleware(apiAnalyzeURL, roleUser)).Methods("POST")
	router.HandleFunc("/api/analyze/link/",
		authMiddleware(apiAnalyzeLink, roleUser)).Methods("POST")
	router.HandleFunc("/api/analyze/html/",
		authMiddleware(apiAnalyzeHTML, roleUser)).Methods("POST")
	//--------------------------------------------------
	router.HandleFunc("/api/indicators/fetch/",
		authMiddleware(apiIndicatorsFetch, roleUser)).Methods("GET")
	router.HandleFunc("/api/indicators/fetch/recent/",
		authMiddleware(apiIndicatorsFetchRecent, roleUser)).Methods("GET")
	router.HandleFunc("/api/indicators/fetch/all/",
		authMiddleware(apiIndicatorsFetchAll, roleUser)).Methods("GET")
	//--------------------------------------------------
	router.HandleFunc("/api/alerts/add/",
		authMiddleware(apiAlertsAdd, roleUser)).Methods("POST")
	router.HandleFunc("/api/reports/add/",
		authMiddleware(apiReportsAdd, roleUser)).Methods("POST")
	//--------------------------------------------------
	router.HandleFunc("/api/reviews/add/",
		authMiddleware(apiReviewsAdd, roleUser)).Methods("POST")

	// Submitter routes.
	router.HandleFunc("/api/indicators/add/",
		authMiddleware(apiIndicatorsAdd, roleSubmitter)).Methods("POST")

	// Admin routes.
	router.HandleFunc(fmt.Sprintf("/api/indicators/details/{ioc:%s}/", regexSHA256),
		authMiddleware(apiIndicatorsDetails, roleAdmin)).Methods("GET")
	router.HandleFunc(fmt.Sprintf("/api/indicators/pending/"),
		authMiddleware(apiIndicatorsFetchPending, roleAdmin)).Methods("GET")
	router.HandleFunc(fmt.Sprintf("/api/indicators/disabled/"),
		authMiddleware(apiIndicatorsFetchDisabled, roleAdmin)).Methods("GET")
	router.HandleFunc("/api/indicators/enable/",
		authMiddleware(apiIndicatorsEnable, roleAdmin)).Methods("POST")
	router.HandleFunc("/api/indicators/disable/",
		authMiddleware(apiIndicatorsDisable, roleAdmin)).Methods("POST")
	//--------------------------------------------------
	router.HandleFunc("/api/alerts/fetch/",
		authMiddleware(apiAlertsFetch, roleAdmin)).Methods("GET")
	//--------------------------------------------------
	router.HandleFunc("/api/reports/fetch/",
		authMiddleware(apiReportsFetch, roleAdmin)).Methods("GET")
	router.HandleFunc(fmt.Sprintf("/api/reports/details/{uuid:%s}/", regexUUID),
		authMiddleware(apiReportsDetails, roleAdmin)).Methods("GET")
	//--------------------------------------------------
	router.HandleFunc("/api/users/pending/",
		authMiddleware(apiUsersPending, roleAdmin)).Methods("GET")
	router.HandleFunc("/api/users/active/",
		authMiddleware(apiUsersActive, roleAdmin)).Methods("GET")
	router.HandleFunc(fmt.Sprintf("/api/users/activate/{uuid:%s}/", regexUUID),
		authMiddleware(apiUsersActivate, roleAdmin)).Methods("GET")
	router.HandleFunc(fmt.Sprintf("/api/users/deactivate/{uuid:%s}/", regexUUID),
		authMiddleware(apiUsersDeactivate, roleAdmin)).Methods("GET")

	router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Warn().Str("uri", r.RequestURI).Msg("File not found")
		errorWithJSON(w, "File not found", http.StatusNotFound, nil)
	})

	hostPort := fmt.Sprintf("%s:%d", flagHost, flagPortNumber)
	srv := &http.Server{
		Handler:      router,
		Addr:         hostPort,
		WriteTimeout: 2 * time.Minute,
		ReadTimeout:  2 * time.Minute,
	}

	log.Info().Str("host", flagHost).Int("port", flagPortNumber).Msg("Starting PhishDetect Node and waiting for requests")
	log.Fatal().Err(srv.ListenAndServe())
}

func main() {
	err := initDatabase()
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to initialize database")
		return
	}

	if flagCreateNewUser {
		createNewUser()
		return
	}

	initLogging()

	err = initServer()
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to initialize server")
		return
	}

	startServer()
}
