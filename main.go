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

	pongo "github.com/flosch/pongo2"
	"github.com/gobuffalo/packr"
	"github.com/gorilla/mux"
	"github.com/mattn/go-colorable"
	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"

	"github.com/phishdetect/phishdetect"
)

const (
	uuidRegex   = "[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[4|5|6|7|8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}"
	base64Regex = "(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})"
	sha1Regex   = "[a-fA-F0-9]{40}"
	sha256Regex = "[a-fA-F0-9]{64}"
)

var (
	createNewUserFlag bool

	flagHost             string
	flagPortNumber       string
	flagMongoURL         string
	flagDockerAPIVersion string
	flagSafeBrowsing     string
	flagBrandsPath       string
	flagYaraPath         string
	flagAdminContacts    string

	enableAPI       bool
	enableGUI       bool
	enableAnalysis  bool
	enforceUserAuth bool

	db *Database

	templatesBox packr.Box
	staticBox    packr.Box
	tmplSet      *pongo.TemplateSet

	sha1RegexCompiled *regexp.Regexp

	customBrands CustomBrands
)

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remote := r.Header.Get("X-Forwarded-For")
		if remote == "" {
			remote = r.RemoteAddr
		}
		log.Debug(remote, " ", r.Method, " ", r.RequestURI)
		next.ServeHTTP(w, r)
	})
}

func init() {
	// Enable debug logging.
	debug := flag.Bool("debug", false, "Enable debug logging")

	// With this flag, instead of starting the server, we create a new user.
	flag.BoolVar(&createNewUserFlag, "create-user", false, "Create a new user")

	// Disable default functionality.
	flagDisableAPI := flag.Bool("disable-api", false, "Disable the API routes")
	flagDisableGUI := flag.Bool("disable-gui", false, "Disable the Web GUI")
	flagDisableAnalysis := flag.Bool("disable-analysis", false, "Disable the ability to analyze links and pages")
	flagDisableUserAuth := flag.Bool("disable-user-auth", false, "Disable requirement of a valid user API key for all operations")

	// Server connection details.
	flag.StringVar(&flagHost, "host", "127.0.0.1", "Specify the host to bind the service on")
	flag.StringVar(&flagPortNumber, "port", "7856", "Specify which port number to bind the service on")
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
	// URL to a page providing contact details for the Node operators.
	flag.StringVar(&flagAdminContacts, "contacts", "", "Specify a link to information or contacts details to be provided to your users")
	flag.Parse()

	if *debug {
		log.SetLevel(log.DebugLevel)
	}
	log.SetFormatter(&log.TextFormatter{
		ForceColors:     true,
		TimestampFormat: "2006-01-02 15:04:05 -0700",
		FullTimestamp:   true,
	})
	log.SetOutput(colorable.NewColorableStdout())

	// Initialize configuration values.
	enableAPI = !*flagDisableAPI
	enableGUI = !*flagDisableGUI
	enableAnalysis = !*flagDisableAnalysis
	enforceUserAuth = !*flagDisableUserAuth

	// Initiate connection to database.
	var err error
	db, err = NewDatabase(flagMongoURL)
	if err != nil {
		log.Fatal("Failed connection to database: ", err.Error())
		return
	}
}

func initServer() {
	log.Info("Enable API: ", enableAPI)
	log.Info("Enable GUI: ", enableGUI)
	log.Info("Enable Analysis: ", enableAnalysis)
	log.Info("Enforce User Auth: ", enforceUserAuth)

	// Initialize SafeBrowsing if an API key was provided.
	if flagSafeBrowsing != "" {
		if _, err := os.Stat(flagSafeBrowsing); err == nil {
			buf, _ := ioutil.ReadFile(flagSafeBrowsing)
			key := string(buf)
			if key != "" {
				phishdetect.AddSafeBrowsingKey(key)
			}
		} else {
			log.Warning("The specified Google SafeBrowsing API key file does not exist: check disabled")
		}
	}

	// Initialize Yara scanner if rule files were specified.
	if flagYaraPath != "" {
		// We do a first compilation of the Yara rules.
		err := phishdetect.LoadYaraRules(flagYaraPath)
		if err != nil {
			log.Error("Failed to initialize Yara scanner: ", err.Error())
		}
		// Then we set up a fsnotify watcher in order to auto-reload Yara
		// rules in case one is created, modified, or removed.
		go watchFolder(flagYaraPath, func() {
			phishdetect.LoadYaraRules(flagYaraPath)
		})
	}

	// Load custom brands.
	if flagBrandsPath != "" {
		customBrands.Path = flagBrandsPath
		// We do a first compilation of the brand definitions.
		err := customBrands.CompileBrands()
		if err != nil {
			log.Error("Failed to compile brands: ", err)
		}
		// Then we setup a fsnofity watcher in order to auto-reload brand
		// definitions in case one is created, modified or removed.
		go watchFolder(customBrands.Path, func() {
			customBrands.CompileBrands()
		})
	}

	// Load templates.
	templatesBox = packr.NewBox("templates")
	staticBox = packr.NewBox("static")
	tmplSet = pongo.NewSet("templates", packrBoxLoader{&templatesBox})

	// Compile sha1 regex (used for key validation).
	sha1RegexCompiled = regexp.MustCompile(sha1Regex)
}

func startServer() {
	fs := http.FileServer(staticBox)

	router := mux.NewRouter()
	router.StrictSlash(true)
	router.Use(loggingMiddleware)

	// Graphical interface routes.
	if enableGUI {
		router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fs))
		router.HandleFunc("/", guiIndex).Methods("GET")
		router.HandleFunc("/register/", guiRegister).Methods("GET", "POST")
		router.HandleFunc("/contacts/", guiContacts).Methods("GET")
		router.HandleFunc("/link/analyze/",
			authMiddleware(guiLinkAnalyze, roleUser)).Methods("POST")
		router.HandleFunc(fmt.Sprintf("/link/{url:%s}/", base64Regex),
			authMiddleware(guiLinkCheck, roleUser)).Methods("GET", "POST")
		router.HandleFunc(fmt.Sprintf("/report/{url:%s}/", base64Regex),
			authMiddleware(guiReport, roleUser)).Methods("GET")
		router.HandleFunc(fmt.Sprintf("/review/{ioc:%s}/", sha256Regex),
			authMiddleware(guiReview, roleUser)).Methods("GET")
	}

	// REST API routes.
	if enableAPI {
		// Non-auth routes.
		router.HandleFunc("/api/config/", apiConfig).Methods("GET")

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

		// Submitter routes.
		router.HandleFunc("/api/indicators/add/",
			authMiddleware(apiIndicatorsAdd, roleSubmitter)).Methods("POST")

		// Admin routes.
		router.HandleFunc(fmt.Sprintf("/api/indicators/details/{ioc:%s}/", sha256Regex),
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
		router.HandleFunc(fmt.Sprintf("/api/reports/details/{uuid:%s}/", uuidRegex),
			authMiddleware(apiReportsDetails, roleAdmin)).Methods("GET")
		//--------------------------------------------------
		router.HandleFunc("/api/users/pending/",
			authMiddleware(apiUsersPending, roleAdmin)).Methods("GET")
		router.HandleFunc("/api/users/active/",
			authMiddleware(apiUsersActive, roleAdmin)).Methods("GET")
		router.HandleFunc(fmt.Sprintf("/api/users/activate/{uuid:%s}/", uuidRegex),
			authMiddleware(apiUsersActivate, roleAdmin)).Methods("GET")
		router.HandleFunc(fmt.Sprintf("/api/users/deactivate/{uuid:%s}/", uuidRegex),
			authMiddleware(apiUsersDeactivate, roleAdmin)).Methods("GET")
	}

	router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Warning("File not found: ", r.RequestURI)
		errorWithJSON(w, "File not found", http.StatusNotFound, nil)
	})

	hostPort := fmt.Sprintf("%s:%s", flagHost, flagPortNumber)
	srv := &http.Server{
		Handler:      router,
		Addr:         hostPort,
		WriteTimeout: 2 * time.Minute,
		ReadTimeout:  2 * time.Minute,
	}

	log.Info("Starting PhishDetect Node on ", hostPort, " and waiting for requests...")
	log.Fatal(srv.ListenAndServe())
}

func main() {
	if createNewUserFlag {
		createNewUser()
		return
	}

	initServer()
	startServer()
}
