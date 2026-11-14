package schema

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// loopbackFetcher swaps the package fetcher for one whose policy allows
// loopback (httptest servers bind 127.0.0.1) while still blocking every other
// non-public destination. The production fetcher, built on defaultHostPolicy,
// is restored on test cleanup.
func loopbackFetcher(t *testing.T) *safeFetcher {
	t.Helper()
	original := fetcher
	policy := HostPolicyFunc(func(_ context.Context, host string) error {
		if isLocalName(host) {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil {
			if ip.IsLoopback() {
				return nil
			}
			if isBlockedIP(ip) {
				return &FetchError{Reason: ReasonHostBlocked, URL: host,
					Err: net.InvalidAddrError("blocked range")}
			}
			return nil
		}
		return defaultHostPolicy(context.Background(), host)
	})
	f := newSafeFetcher(policy)
	fetcher = f
	t.Cleanup(func() { fetcher = original })
	return f
}

func expectFetchError(t *testing.T, err error, reason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with reason %q, got nil", reason)
	}
	fe, ok := err.(*FetchError)
	if !ok {
		t.Fatalf("expected *FetchError, got %T: %v", err, err)
	}
	if fe.Reason != reason {
		t.Fatalf("expected reason %q, got %q (%v)", reason, fe.Reason, err)
	}
}

const articleHTML = `<!DOCTYPE html>
<html lang="en">
<head><title>The Art of Indexing Web Pages</title></head>
<body>
<nav>home about login</nav>
<article>
<h1>The Art of Indexing Web Pages</h1>
<p>Search engines turn the unstructured web into something queryable. The
first step in that pipeline is fetching a document safely, without letting a
single link reach internal services or exhaust the indexer's memory.</p>
<p>A robust fetcher validates the scheme, resolves and checks every host
before connecting, re-checks each redirect hop, limits the response size, and
verifies that the bytes returned really are the kind of document the caller
asked for. Only then does the readability stage extract a title and a body.</p>
<p>The extracted title and body must both survive the pipeline, because an
article with no text adds nothing to the inverted index and should be treated
as a failed extraction rather than stored as an empty record.</p>
</article>
<footer>copyright irrelevant boilerplate</footer>
</body>
</html>`

func TestScrapeRejectsNonHTTPSchemes(t *testing.T) {
	for _, link := range []string{
		"file:///etc/passwd",
		"ftp://example.com/notes.txt",
		"gopher://example.com/",
		"javascript:alert(1)",
	} {
		_, err := Scrape(link)
		expectFetchError(t, err, ReasonInvalidURL)
	}
}

func TestScrapeRejectsPrivateAndLocalAddresses(t *testing.T) {
	blocked := []string{
		"http://127.0.0.1/",
		"http://127.0.0.2:8080/admin",
		"http://localhost/",
		"http://10.0.0.5/metadata",
		"http://192.168.1.10/",
		"http://172.16.4.9/",
		"http://169.254.169.254/latest/meta-data/", // cloud metadata endpoint
		"http://0.0.0.0/",
		"http://[::1]/",
		"http://[fc00::1]/",
		"http://[fe80::1]/",
		"http://100.64.0.1/", // CGNAT
		// Alternate encodings of 127.0.0.1 must not slip past net.ParseIP:
		// the resolver rejects them, and the dial-time policy check closes
		// the gap if the platform resolver ever resolves them.
		"http://127.1/",
		"http://2130706433/",
		"http://0177.0.0.1/",
		"http://0x7f.0.0.1/",
	}
	for _, link := range blocked {
		_, err := Scrape(link)
		expectFetchError(t, err, ReasonHostBlocked)
	}
}

func TestScrapeRejectsURLsWithCredentials(t *testing.T) {
	_, err := Scrape("http://user:secret@example.com/article")
	expectFetchError(t, err, ReasonInvalidURL)
}

func TestScrapeRedirectToPrivateAddressIsBlocked(t *testing.T) {
	loopbackFetcher(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("handler for blocked redirect target must never be reached; got request %s", r.URL)
	}))
	defer target.Close()

	// The redirect target is a link-local/metadata-style literal, which the
	// test policy (and the production policy) blocks.
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer redirector.Close()

	_, err := Scrape(redirector.URL + "/start")
	expectFetchError(t, err, ReasonHostBlocked)
}

func TestScrapeRedirectToNonHTTPSchemeIsBlocked(t *testing.T) {
	loopbackFetcher(t)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "file:///etc/passwd", http.StatusFound)
	}))
	defer redirector.Close()

	_, err := Scrape(redirector.URL + "/start")
	expectFetchError(t, err, ReasonInvalidURL)
}

func TestScrapeFollowsValidRedirectToArticle(t *testing.T) {
	loopbackFetcher(t)
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(articleHTML))
	}))
	defer final.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/article", http.StatusFound)
	}))
	defer redirector.Close()

	data, err := Scrape(redirector.URL + "/start")
	if err != nil {
		t.Fatalf("expected redirect to be followed, got %v", err)
	}
	if data.Title != "The Art of Indexing Web Pages" {
		t.Fatalf("title not preserved: %q", data.Title)
	}
	if !strings.Contains(data.Content, "inverted index") {
		t.Fatalf("article body not preserved, got %q", data.Content)
	}
	if data.Link != redirector.URL+"/start" {
		t.Fatalf("original link must be retained, got %q", data.Link)
	}
	if data.Tags == nil {
		t.Fatal("tags slice should be initialized")
	}
}

func TestScrapeRejectsTooManyRedirects(t *testing.T) {
	loopbackFetcher(t)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always bounce to a fresh path on the same (allowed) loopback host.
		http.Redirect(w, r, r.URL.Path+"/x", http.StatusFound)
	}))
	defer redirector.Close()

	_, err := Scrape(redirector.URL + "/loop")
	expectFetchError(t, err, ReasonTooManyRedirects)
}

func TestScrapeRejectsOversizedResponseByContentLength(t *testing.T) {
	loopbackFetcher(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Length", "20971520")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, err := Scrape(server.URL + "/big")
	expectFetchError(t, err, ReasonResponseTooLarge)
}

func TestScrapeRejectsOversizedStreamingResponse(t *testing.T) {
	loopbackFetcher(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No Content-Length: chunked, so the limit can only be enforced while
		// reading. Flush regularly so bytes actually leave the server.
		flusher, _ := w.(http.Flusher)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		chunk := strings.Repeat("a", 4096)
		for i := 0; i < (maxResponseBytes/4096)+4; i++ {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
	}))
	defer server.Close()

	_, err := Scrape(server.URL + "/stream")
	expectFetchError(t, err, ReasonResponseTooLarge)
}

func TestScrapeRejectsNonTextContentType(t *testing.T) {
	loopbackFetcher(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte(articleHTML))
	}))
	defer server.Close()

	_, err := Scrape(server.URL + "/blob")
	expectFetchError(t, err, ReasonUnsupportedType)
}

func TestScrapeAcceptsMissingContentTypeViaSniffing(t *testing.T) {
	loopbackFetcher(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Deliberately no Content-Type: sniffing must identify the HTML body.
		w.Header().Del("Content-Type")
		_, _ = w.Write([]byte(articleHTML))
	}))
	defer server.Close()

	data, err := Scrape(server.URL + "/notype")
	if err != nil {
		t.Fatalf("HTML body with no Content-Type should pass sniffing: %v", err)
	}
	if data.Title != "The Art of Indexing Web Pages" || data.Content == "" {
		t.Fatalf("title/body lost: %+v", data)
	}
}

func TestScrapeRejectsDisguisedMIME(t *testing.T) {
	loopbackFetcher(t)
	// The server lies about the type; the leading bytes are a PNG signature,
	// so content sniffing must catch the mismatch.
	png := append([]byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a},
		[]byte(strings.Repeat("x", 256))...)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(png)
	}))
	defer server.Close()

	_, err := Scrape(server.URL + "/fake")
	expectFetchError(t, err, ReasonUnsupportedType)
}

func TestScrapeExtractsLegitimateArticle(t *testing.T) {
	loopbackFetcher(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(articleHTML))
	}))
	defer server.Close()

	data, err := Scrape(server.URL + "/article")
	if err != nil {
		t.Fatalf("legitimate article should scrape, got %v", err)
	}
	if data.Title != "The Art of Indexing Web Pages" {
		t.Fatalf("expected extracted title, got %q", data.Title)
	}
	if !strings.Contains(data.Content, "readability stage extract") {
		t.Fatalf("expected body text in content, got %q", data.Content)
	}
	if strings.Contains(data.Content, "<") || strings.Contains(data.Content, ">") {
		t.Fatalf("HTML tags should be stripped from content, got %q", data.Content)
	}
}

func TestScrapeKeepsServingAfterFailure(t *testing.T) {
	loopbackFetcher(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(articleHTML))
	}))
	defer server.Close()

	// First call is refused (private address)...
	if _, err := Scrape("http://192.168.0.1/secret"); err == nil {
		t.Fatal("expected private address to be blocked")
	}
	// ...and the fetcher must still serve a legitimate request afterwards.
	data, err := Scrape(server.URL + "/article")
	if err != nil {
		t.Fatalf("fetcher did not recover after rejection: %v", err)
	}
	if data.Title == "" || data.Content == "" {
		t.Fatal("recovered scrape lost title or body")
	}
}

func TestIsYouTubeURLMatchesHostNotSubstring(t *testing.T) {
	valid := []string{
		"https://www.youtube.com/watch?v=dQw4w9WgXcQ",
		"https://youtube.com/watch?v=abc",
		"https://m.youtube.com/watch?v=abc",
		"https://music.youtube.com/watch?v=abc",
		"https://youtu.be/abc",
		"http://www.youtube.com/watch?v=abc",
	}
	for _, link := range valid {
		if !isYouTubeURL(link) {
			t.Errorf("expected %q to be recognized as YouTube", link)
		}
	}
	impostors := []string{
		// The old substring check treated these as YouTube.
		"https://example.com/www.youtube.com",
		"https://notyoutube.com/watch?v=abc",
		"https://www.youtube.com.evil.example/",
		"ftp://www.youtube.com/video",
		"not a url at all",
		"",
	}
	for _, link := range impostors {
		if isYouTubeURL(link) {
			t.Errorf("expected %q NOT to be recognized as YouTube", link)
		}
	}
}

func TestIsBlockedIPClassifiesRanges(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.1", "172.31.255.255",
		"169.254.169.254", "0.0.0.0", "255.255.255.255", "224.0.0.1",
		"100.64.0.1", "198.18.0.1", "192.0.2.7", "198.51.100.7", "203.0.113.7",
		"::1", "::", "fc00::1", "fe80::1", "ff02::1", "::ffff:127.0.0.1",
		"::ffff:169.254.169.254",
	}
	for _, s := range blocked {
		if !isBlockedIP(net.ParseIP(s)) {
			t.Errorf("expected %s to be blocked", s)
		}
	}
	public := []string{
		"8.8.8.8", "1.1.1.1", "93.184.216.34", "172.32.0.1", "100.128.0.1",
		"2606:4700:4700::1111", "2001:4860:4860::8888",
	}
	for _, s := range public {
		if isBlockedIP(net.ParseIP(s)) {
			t.Errorf("expected %s to be allowed", s)
		}
	}
}
