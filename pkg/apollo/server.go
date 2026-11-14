package apollo

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/amirgamil/apollo/pkg/apollo/backend"
	"github.com/amirgamil/apollo/pkg/apollo/schema"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	jsoniter "github.com/json-iterator/go"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

//records which are stored locally, which have been added via Apollo directly
const localRecordsPath = "./data/local.json"

//global used to quickly access details when searching
var currentSearchResults map[string]string

func index(w http.ResponseWriter, r *http.Request) {
	indexFile, err := os.Open("./static/index.html")
	if err != nil {
		io.WriteString(w, "error reading index")
		return
	}
	defer indexFile.Close()

	io.Copy(w, indexFile)
}

// scrapeFn is indirection over schema.Scrape so tests can exercise the HTTP
// handler without relying on the package-wide (loopback-blocking) fetcher.
var scrapeFn = schema.Scrape

// scrapeErrorResponse is the stable error envelope returned by /scrape. Reason
// is always one of the schema.Reason* constants, so clients can branch on it.
type scrapeErrorResponse struct {
	Error  string `json:"error"`
	Reason string `json:"reason"`
	URL    string `json:"url"`
}

func scrape(w http.ResponseWriter, r *http.Request) {
	linkToScrape := r.FormValue("q")
	w.Header().Set("Content-Type", "application/json")
	result, err := scrapeFn(linkToScrape)
	if err != nil {
		// A single bad or blocked link must never take the process down: log
		// and answer with the structured rejection reason instead.
		log.Printf("scrape rejected for %q: %v", linkToScrape, err)
		resp := scrapeErrorResponse{Error: err.Error(), Reason: schema.ReasonFetchFailed, URL: linkToScrape}
		var fetchErr *schema.FetchError
		if errors.As(err, &fetchErr) {
			resp.Reason = fetchErr.Reason
			if fetchErr.URL != "" {
				resp.URL = fetchErr.URL
			}
		}
		w.WriteHeader(statusForScrapeReason(resp.Reason))
		json.NewEncoder(w).Encode(resp)
		return
	}
	json.NewEncoder(w).Encode(result)
}

// statusForScrapeReason maps stable rejection reasons onto HTTP status codes.
// Caller-side mistakes (bad URL, blocked host, redirect policy) are 4xx;
// transport failures remain 417 as the original endpoint used.
func statusForScrapeReason(reason string) int {
	switch reason {
	case schema.ReasonInvalidURL, schema.ReasonHostBlocked:
		return http.StatusBadRequest
	case schema.ReasonTooManyRedirects, schema.ReasonUnsupportedType, schema.ReasonResponseTooLarge:
		return http.StatusUnprocessableEntity
	default:
		return http.StatusExpectationFailed
	}
}

func addData(w http.ResponseWriter, r *http.Request) {
	var newData schema.Data
	err := jsoniter.NewDecoder(r.Body).Decode(&newData)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	} else {
		backend.AddNewEntryToLocalData(newData)
		w.WriteHeader(http.StatusAccepted)
	}
}

func search(w http.ResponseWriter, r *http.Request) {
	searchQuery := r.FormValue("q")
	//"erase" current result in preparation for new search
	currentSearchResults = make(map[string]string)
	w.Header().Set("Content-Encoding", "gz")
	w.Header().Set("Content-Type", "application/json")
	fmt.Println(searchQuery)
	//TODO: add logic for OR
	results, err := backend.Search(searchQuery, "AND", currentSearchResults)
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
	}
	_, ok := w.(http.Flusher)
	if !ok {
		//streaming not supported
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	} else {
		// w.Header().Set("Cache-Control", "no-cache")
		// w.Header().Set("Connection", "keep-alive")
		// w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
		// for _, result := range results.Data {
		// 	b, err := jsoniter.Marshal(result)
		// 	if err != nil {
		// 		fmt.Printf("could not json marshall reponse item %#v: %v\n", result, err)
		// 		continue
		// 	}
		// 	fmt.Fprintf(w, "%s\n", string(b))
		// 	fmt.Println(result.Title)
		// 	f.Flush()
		// }
		// fmt.Println("results : ", results)
		// gz := gzip.NewWriter(w)
		// defer gz.Close()

		jsoniter.NewEncoder(w).Encode(results)
	}
}

//get the full text of a record when expanded for detail
func getRecord(w http.ResponseWriter, r *http.Request) {
	recordTitle := r.FormValue("q")
	record, inMap := currentSearchResults[recordTitle]
	if len(currentSearchResults) == 0 || !inMap {
		w.WriteHeader(http.StatusBadRequest)
	} else {
		jsoniter.NewEncoder(w).Encode(record)
	}

}

func authenticatePassword(w http.ResponseWriter, r *http.Request) {
	type Request struct {
		Password string `json:"password"`
	}
	var request Request
	json.NewDecoder(r.Body).Decode(&request)
	if isValidPassword(request.Password) {
		w.WriteHeader(http.StatusAccepted)
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}
}

func isValidPassword(password string) bool {
	err := godotenv.Load()
	check(err)
	truePass := os.Getenv("PASSWORD")
	return truePass == password
}

func Start() {
	srv := &http.Server{
		Handler:      newRouter(),
		Addr:         "0.0.0.0:8993",
		WriteTimeout: 60 * time.Second,
		ReadTimeout:  60 * time.Second,
	}
	log.Printf("Server listening on %s\n", srv.Addr)
	log.Fatal(srv.ListenAndServe())

}

// newRouter wires every API route. It is split out of Start so httptest can
// exercise the full handler stack without binding a network port.
func newRouter() *mux.Router {
	r := mux.NewRouter()
	currentSearchResults = make(map[string]string)

	//will need to some kind of API call to ingest data
	r.Methods("POST").Path("/search").HandlerFunc(search)
	r.Methods("POST").Path("/scrape").HandlerFunc(scrape)
	r.Methods("POST").Path("/addData").HandlerFunc(addData)
	r.Methods("POST").Path("/authenticate").HandlerFunc(authenticatePassword)
	r.Methods("POST").Path("/getRecordDetail").HandlerFunc(getRecord)
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))
	r.PathPrefix("/").HandlerFunc(index)
	return r
}
