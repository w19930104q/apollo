package apollo

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/amirgamil/apollo/pkg/apollo/schema"
)

func TestScrapeHandlerReturnsStableRejectionReason(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/scrape?q=http://127.0.0.1/", nil)
	rec := httptest.NewRecorder()
	newRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a blocked host, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	var resp scrapeErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("rejection body must be valid JSON: %v (%s)", err, rec.Body.String())
	}
	if resp.Reason != schema.ReasonHostBlocked {
		t.Fatalf("expected stable reason %q, got %q", schema.ReasonHostBlocked, resp.Reason)
	}
	if resp.Error == "" {
		t.Fatal("error message should be populated for the client")
	}
}

func TestScrapeHandlerKeepsServingAfterFailure(t *testing.T) {
	router := newRouter()

	// First request is refused with a structured reason...
	req := httptest.NewRequest(http.MethodPost, "/scrape?q=file:///etc/passwd", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("expected a non-200 status for a non-HTTP scheme")
	}
	var first scrapeErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &first); err != nil {
		t.Fatalf("rejection body must be valid JSON: %v", err)
	}
	if first.Reason != schema.ReasonInvalidURL {
		t.Fatalf("expected %q, got %q", schema.ReasonInvalidURL, first.Reason)
	}

	// ...the process must still be alive and serving. Stub the scrape
	// function because the production fetcher blocks loopback test servers.
	original := scrapeFn
	scrapeFn = func(link string) (schema.Data, error) {
		return schema.Data{Title: "Recovered", Link: link, Content: "body text", Tags: []string{}}, nil
	}
	t.Cleanup(func() { scrapeFn = original })

	req = httptest.NewRequest(http.MethodPost, "/scrape?q=https://example.com/article", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 after recovery, got %d: %s", rec.Code, rec.Body.String())
	}
	var data schema.Data
	if err := json.Unmarshal(rec.Body.Bytes(), &data); err != nil {
		t.Fatalf("success body must be valid JSON: %v", err)
	}
	if data.Title != "Recovered" || data.Content != "body text" {
		t.Fatalf("title and body must be preserved: %+v", data)
	}
}

func TestSearchAPIUnaffectedByScrapeRejections(t *testing.T) {
	router := newRouter()

	// A rejected scrape (cloud metadata address) must not disturb the rest of
	// the API surface.
	req := httptest.NewRequest(http.MethodPost, "/scrape?q=http://169.254.169.254/latest/meta-data/", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("expected the metadata address to be blocked")
	}
	var resp scrapeErrorResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Reason != schema.ReasonHostBlocked {
		t.Fatalf("expected %q, got %q", schema.ReasonHostBlocked, resp.Reason)
	}

	// The search endpoint still answers. Stop words tokenize to nothing, so
	// Search returns its empty-query 204 without needing index globals, which
	// are only initialized by the full server binary.
	req = httptest.NewRequest(http.MethodPost, "/search?q=the%20and%20of", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected the search API to keep serving (204), got %d", rec.Code)
	}
}
