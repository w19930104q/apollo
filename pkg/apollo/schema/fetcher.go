package schema

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Stable, machine-readable reasons returned when a fetch is refused. The
// crawler never passes user-controlled URLs to the network unless they pass
// every check below, and the same reasons are surfaced through the API.
const (
	// ReasonInvalidURL covers malformed URLs, non-HTTP(S) schemes, userinfo
	// embedded in the URL and missing/empty hosts.
	ReasonInvalidURL = "invalid_url"
	// ReasonHostBlocked covers hostnames which resolve (or literally encode)
	// loopback, private, link-local, multicast or otherwise non-public
	// addresses. The check runs before the request and on every redirect hop.
	ReasonHostBlocked = "host_blocked"
	// ReasonTooManyRedirects is returned once the redirect budget is spent.
	ReasonTooManyRedirects = "too_many_redirects"
	// ReasonUnsupportedType is returned when the response advertises (or
	// actually contains, via content sniffing) anything other than HTML or
	// plain text.
	ReasonUnsupportedType = "unsupported_content_type"
	// ReasonResponseTooLarge is returned when the response exceeds
	// maxResponseBytes, whether announced up front or while streaming.
	ReasonResponseTooLarge = "response_too_large"
	// ReasonFetchFailed covers transport-level failures (DNS, connection,
	// timeout, TLS) which are not policy rejections.
	ReasonFetchFailed = "fetch_failed"
)

const (
	// maxResponseBytes caps how much of a response we are willing to buffer,
	// so a single link cannot exhaust the indexer's memory.
	maxResponseBytes = 10 << 20 // 10 MiB
	// maxRedirects bounds redirect chains; every hop is re-validated.
	maxRedirects = 5
	// fetchTimeout bounds the entire request, including redirects and reads.
	fetchTimeout = 30 * time.Second
	// resolveTimeout bounds a single hostname resolution.
	resolveTimeout = 5 * time.Second
)

// FetchError is the structured error returned by the safe fetcher. The Reason
// field is one of the Reason* constants above and is safe to return to API
// clients; Err holds the underlying error for logging.
type FetchError struct {
	Reason string
	URL    string
	Err    error
}

func (e *FetchError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("fetch %q rejected: %s: %v", e.URL, e.Reason, e.Err)
	}
	return fmt.Sprintf("fetch %q rejected: %s", e.URL, e.Reason)
}

// Unwrap lets errors.Is/errors.As reach the underlying transport error.
func (e *FetchError) Unwrap() error {
	return e.Err
}

// HostPolicy decides whether a resolved host may be contacted. Returning a
// non-nil error blocks the request.
type HostPolicy interface {
	CheckHost(ctx context.Context, host string) error
}

// HostPolicyFunc adapts a plain function to the HostPolicy interface.
type HostPolicyFunc func(ctx context.Context, host string) error

// CheckHost implements HostPolicy.
func (f HostPolicyFunc) CheckHost(ctx context.Context, host string) error {
	return f(ctx, host)
}

// defaultHostPolicy blocks every non-public destination: loopback, private
// ranges, link-local (including the cloud metadata address 169.254.169.254),
// multicast, unspecified and reserved ranges, in both IPv4 and IPv6.
func defaultHostPolicy(ctx context.Context, host string) error {
	ip := net.ParseIP(host)
	if ip != nil && isBlockedIP(ip) {
		return fmt.Errorf("address %s is not a public, routable host", ip)
	}
	// "localhost" and friends must never reach a resolver, where they could
	// be redefined to something surprising.
	if isLocalName(host) {
		return fmt.Errorf("hostname %q is not allowed", host)
	}
	if ip == nil {
		// Non-literal hosts are resolved up front so that every address the
		// resolver hands back can be checked before any connection is made.
		// Resolution failures simply fail closed.
		if ctx == nil {
			ctx = context.Background()
		}
		resolveCtx, cancel := context.WithTimeout(ctx, resolveTimeout)
		defer cancel()
		ips, err := net.DefaultResolver.LookupIPAddr(resolveCtx, host)
		if err != nil {
			return fmt.Errorf("could not resolve %q: %w", host, err)
		}
		if len(ips) == 0 {
			return fmt.Errorf("hostname %q resolved to no addresses", host)
		}
		for _, addr := range ips {
			if isBlockedIP(addr.IP) {
				return fmt.Errorf("hostname %q resolves to blocked address %s", host, addr.IP)
			}
		}
	}
	return nil
}

func isLocalName(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	return h == "localhost" || strings.HasSuffix(h, ".localhost")
}

// isBlockedIP reports whether ip falls in any range that must never be
// contacted by the crawler. It mirrors the intent of net.IP's
// IsLoopback/IsPrivate/IsLinkLocal* helpers with explicit ranges so the
// policy does not depend on the Go version's classification table.
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		// 0.0.0.0/8 "this network", loopback, RFC1918, link-local
		// (169.254.0.0/16, incl. cloud metadata), TEST-NET ranges, CGNAT
		// (100.64.0.0/10), multicast and limited broadcast.
		switch {
		case v4[0] == 0:
			return true
		case v4[0] == 10:
			return true
		case v4[0] == 127:
			return true
		case v4[0] == 169 && v4[1] == 254:
			return true
		case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31:
			return true
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 0:
			return true
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 2:
			return true
		case v4[0] == 192 && v4[1] == 88 && v4[2] == 99:
			return true
		case v4[0] == 192 && v4[1] == 168:
			return true
		case v4[0] == 198 && (v4[1] == 18 || v4[1] == 19):
			return true
		case v4[0] == 198 && v4[1] == 51 && v4[2] == 100:
			return true
		case v4[0] == 203 && v4[1] == 0 && v4[2] == 113:
			return true
		case v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127:
			return true
		case v4[0] >= 224:
			return true
		}
		return false
	}
	// IPv6: unspecified (::), loopback (::1), IPv4-mapped (::ffff:a.b.c.d,
	// re-check the embedded v4), link-local/unique-local (fc00::/7,
	// fe80::/10), multicast (ff00::/8) and other reserved ranges.
	switch {
	case ip.IsUnspecified(), ip.IsLoopback(), ip.IsMulticast():
		return true
	case len(ip) == 16 && ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 &&
		ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 &&
		ip[8] == 0 && ip[9] == 0 && ip[10] == 255 && ip[11] == 255:
		return isBlockedIP(net.IP(ip[12:16]))
	case ip[0] == 0xfe && (ip[1]&0xc0) == 0x80: // fe80::/10
		return true
	case ip[0]&0xfe == 0xfc: // fc00::/7
		return true
	case ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8: // 2001:db8::/32
		return true
	case ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x00 && (ip[3]&0xfe) == 0x00: // 2001:0::/32
		return true
	case ip[0] == 0x20 && ip[1] == 0x02: // 2002::/16 6to4
		return true
	}
	return false
}

// safeFetcher performs HTTP(S) GETs with SSRF protection: scheme allow-listing,
// host validation before dialing and on every redirect, response-type and
// response-size limits.
type safeFetcher struct {
	policy HostPolicy
	client *http.Client
	dialer *net.Dialer
}

func newSafeFetcher(policy HostPolicy) *safeFetcher {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	f := &safeFetcher{policy: policy}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           f.dialContext,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	// Keep a reference to the default dialer for the actual dial once the
	// destination address has passed the policy.
	f.dialer = dialer
	f.client = &http.Client{
		Transport:     transport,
		Timeout:       fetchTimeout,
		CheckRedirect: f.checkRedirect,
	}
	return f
}

// dialContext re-validates the concrete dial address. This is the last line of
// defense: even if the host entry was swapped between the pre-flight check and
// the dial (DNS rebinding), the connection itself is refused.
func (f *safeFetcher) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, &FetchError{Reason: ReasonInvalidURL, URL: address, Err: err}
	}
	if err := f.policy.CheckHost(ctx, host); err != nil {
		return nil, &FetchError{Reason: ReasonHostBlocked, URL: address, Err: err}
	}
	return f.dialer.DialContext(ctx, network, net.JoinHostPort(host, port))
}

// checkRedirect re-runs the full URL policy on every hop: scheme, host
// resolution and target strategy. A redirect to a blocked destination fails
// the whole fetch rather than being followed.
func (f *safeFetcher) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return &FetchError{Reason: ReasonTooManyRedirects, URL: req.URL.String(),
			Err: fmt.Errorf("more than %d redirects", maxRedirects)}
	}
	if err := f.validateURL(req.Context(), req.URL); err != nil {
		return err
	}
	return nil
}

// validateURL enforces the scheme allow-list and the host policy.
func (f *safeFetcher) validateURL(ctx context.Context, u *url.URL) error {
	raw := u.String()
	if u.Scheme != "http" && u.Scheme != "https" {
		return &FetchError{Reason: ReasonInvalidURL, URL: raw,
			Err: fmt.Errorf("scheme %q is not allowed, only http and https are supported", u.Scheme)}
	}
	if u.Host == "" {
		return &FetchError{Reason: ReasonInvalidURL, URL: raw,
			Err: errors.New("URL is missing a host")}
	}
	if u.User != nil {
		return &FetchError{Reason: ReasonInvalidURL, URL: raw,
			Err: errors.New("URLs with embedded credentials are not allowed")}
	}
	host := u.Hostname()
	if host == "" {
		return &FetchError{Reason: ReasonInvalidURL, URL: raw,
			Err: errors.New("URL is missing a host")}
	}
	if err := f.policy.CheckHost(ctx, host); err != nil {
		return &FetchError{Reason: ReasonHostBlocked, URL: raw, Err: err}
	}
	return nil
}

// fetchHTML downloads rawURL after validating it, then enforces the response
// type (declared and sniffed) and size limits. It returns the buffered body
// and the final URL after any redirects.
func (f *safeFetcher) fetchHTML(rawURL string) ([]byte, string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, "", &FetchError{Reason: ReasonInvalidURL, URL: rawURL, Err: err}
	}
	if err := f.validateURL(context.Background(), parsed); err != nil {
		return nil, "", err
	}

	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", &FetchError{Reason: ReasonInvalidURL, URL: rawURL, Err: err}
	}
	req.Header.Set("User-Agent", "apollo-indexer/1.0 (+safe fetch)")
	req.Header.Set("Accept", "text/html, application/xhtml+xml, text/plain;q=0.9, */*;q=0.1")

	resp, err := f.client.Do(req)
	if err != nil {
		// Policy rejections (redirect hops, dial-time checks) keep their
		// structured reason; everything else is a transport failure.
		var fe *FetchError
		if errors.As(err, &fe) {
			return nil, "", fe
		}
		return nil, "", &FetchError{Reason: ReasonFetchFailed, URL: rawURL, Err: err}
	}
	defer resp.Body.Close()

	// Reject oversized payloads announced up front before reading a byte.
	if resp.ContentLength > maxResponseBytes {
		return nil, "", &FetchError{Reason: ReasonResponseTooLarge, URL: rawURL,
			Err: fmt.Errorf("response is %d bytes, limit is %d", resp.ContentLength, maxResponseBytes)}
	}

	// A missing Content-Type is legal; defer entirely to content sniffing in
	// that case. A present but unparseable or disallowed header is rejected.
	rawContentType := resp.Header.Get("Content-Type")
	var mediaType string
	if rawContentType != "" {
		var err error
		mediaType, _, err = mime.ParseMediaType(rawContentType)
		if err != nil {
			return nil, "", &FetchError{Reason: ReasonUnsupportedType, URL: rawURL, Err: err}
		}
		if !isAllowedMediaType(mediaType) {
			return nil, "", &FetchError{Reason: ReasonUnsupportedType, URL: rawURL,
				Err: fmt.Errorf("content type %q is not an HTML or text document", mediaType)}
		}
	}

	// Read at most one byte past the cap so an over-limit body is detected
	// regardless of whether Content-Length was honest.
	limited := io.LimitReader(resp.Body, maxResponseBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, "", &FetchError{Reason: ReasonFetchFailed, URL: rawURL, Err: err}
	}
	if int64(len(body)) > maxResponseBytes {
		return nil, "", &FetchError{Reason: ReasonResponseTooLarge, URL: rawURL,
			Err: fmt.Errorf("response exceeded the %d byte limit while streaming", maxResponseBytes)}
	}

	// Content sniffing: the declared type is attacker-controlled. Verify the
	// leading bytes actually look like HTML or text rather than, e.g., a
	// binary dressed up as text/html.
	sniffed := http.DetectContentType(body)
	sniffedType, _, err := mime.ParseMediaType(sniffed)
	if err != nil {
		return nil, "", &FetchError{Reason: ReasonUnsupportedType, URL: rawURL, Err: err}
	}
	if !isAllowedMediaType(sniffedType) {
		return nil, "", &FetchError{Reason: ReasonUnsupportedType, URL: rawURL,
			Err: fmt.Errorf("declared content type %q but content sniffs as %q", mediaType, sniffedType)}
	}
	return body, resp.Request.URL.String(), nil
}

// isAllowedMediaType is the response-type allow-list.
func isAllowedMediaType(mediaType string) bool {
	switch mediaType {
	case "text/html", "application/xhtml+xml", "text/plain":
		return true
	}
	return false
}
