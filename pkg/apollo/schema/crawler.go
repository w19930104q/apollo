package schema

import (
	"bytes"
	"context"
	"errors"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"

	readability "github.com/go-shiori/go-readability"
)

// fetcher is the package-wide fetcher used by Scrape. It is a variable so
// tests can swap in a fetcher whose host policy permits loopback httptest
// servers; production always uses defaultHostPolicy.
var fetcher = newSafeFetcher(HostPolicyFunc(defaultHostPolicy))

// tagStripper removes any HTML tags left in readability's text content.
var tagStripper = regexp.MustCompile(`(<[^>]+>)`)

// Scrape fetches and extracts a link into a Data record. Every URL is passed
// through the safe fetcher first: only HTTP(S) URLs whose hosts resolve to
// public addresses are fetched, redirects are re-validated hop by hop, and
// response type and size are bounded. Refusals come back as *FetchError with
// a stable Reason.
func Scrape(link string) (Data, error) {
	if isYouTubeURL(link) {
		return handleYouTubeVideo(link)
	}
	return scrapeArticle(link)
}

// scrapeArticle downloads an article through the safe fetcher and extracts its
// title and body. Both fields are preserved: an empty title or empty body is a
// failed extraction rather than silently indexed blank content.
func scrapeArticle(link string) (Data, error) {
	body, finalURL, err := fetcher.fetchHTML(link)
	if err != nil {
		return Data{}, err
	}
	parsedURL, err := url.Parse(finalURL)
	if err != nil {
		return Data{}, &FetchError{Reason: ReasonFetchFailed, URL: finalURL, Err: err}
	}
	article, err := readability.FromReader(bytes.NewReader(body), parsedURL)
	if err != nil {
		return Data{}, &FetchError{Reason: ReasonFetchFailed, URL: link,
			Err: errors.New("could not parse article: " + err.Error())}
	}
	content := tagStripper.ReplaceAllString(article.TextContent, "")
	if strings.TrimSpace(article.Title) == "" || strings.TrimSpace(content) == "" {
		return Data{}, &FetchError{Reason: ReasonFetchFailed, URL: link,
			Err: errors.New("article extraction produced no title or body")}
	}
	return Data{
		Title:   article.Title,
		Link:    link,
		Content: content,
		Tags:    make([]string, 0),
	}, nil
}

// isYouTubeURL identifies YouTube links by parsed host instead of substring
// matching, so a page such as https://example.com/www.youtube.com is not
// mistaken for a video.
func isYouTubeURL(link string) bool {
	parsed, err := url.Parse(link)
	if err != nil {
		return false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	switch host {
	case "www.youtube.com", "youtube.com", "m.youtube.com", "music.youtube.com", "youtu.be":
		return true
	}
	return false
}

// handleYouTubeVideo validates the link against the same host policy as
// ordinary articles before invoking youtube-dl, and passes the URL as an
// argument (never through a shell) so it cannot inject commands.
func handleYouTubeVideo(link string) (Data, error) {
	parsed, err := url.Parse(link)
	if err != nil {
		return Data{}, &FetchError{Reason: ReasonInvalidURL, URL: link, Err: err}
	}
	if err := fetcher.validateURL(context.Background(), parsed); err != nil {
		return Data{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "youtube-dl",
		"-o", "%(title)s", "--write-srt", "--sub-lang", "en", "--skip-download", link)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stdout
	if err := cmd.Run(); err != nil {
		log.Println("Error running youtube-dl: ", err, stdout.String())
		return Data{}, &FetchError{Reason: ReasonFetchFailed, URL: link,
			Err: errors.New("error downloading the youtube video")}
	}
	log.Println(stdout.String())
	content, title, err := readFromSubtitlesFile()
	if err != nil {
		return Data{}, &FetchError{Reason: ReasonFetchFailed, URL: link,
			Err: errors.New("error loading the subtitles of the video")}
	}
	return Data{Title: title, Link: link, Content: content, Tags: make([]string, 0)}, nil
}

func readFromSubtitlesFile() (string, string, error) {
	files, err := ioutil.ReadDir("./")
	if err != nil {
		log.Println("Error reading the files of the YouTube video: ", err)
		return "", "", nil
	}
	for _, file := range files {
		//find the vtt file which is the format of the downloaded subtitles
		r, err := regexp.MatchString(".vtt", file.Name())
		if err == nil && r {
			//found file
			output, err := readVTTFile(file.Name())
			removeVTTFille(file.Name())
			if err != nil {
				return "", "", err
			}
			regexTitle, _ := regexp.Compile(`(\.en)?\.vtt`)
			title := regexTitle.ReplaceAllString(file.Name(), "")
			return output, title, nil
		}
	}
	return "", "", errors.New("Error reading subtitles!")
}

func removeVTTFille(name string) error {
	err := os.Remove(name)
	if err != nil {
		log.Println("Error removing file: ", err)
		return err
	}
	return nil
}

func readVTTFile(fileName string) (string, error) {
	file, err := os.Open(fileName)
	if err != nil {
		log.Println("Error opening the VTT file: ", err)
		return "", err
	}
	output, err := ioutil.ReadAll(file)
	if err != nil {
		log.Println("Error reading the VTT file: ", err)
		return "", err
	}
	//rule to remove everything but the text of the vtt file
	regexRule := "\n?([0-9]+):([0-9]+):([0-9]+).([0-9]+) --> ([0-9]+):([0-9]+):([0-9]+).([0-9]+)"
	r, _ := regexp.Compile(regexRule)
	if r.Match(output) {
		textVideo := r.ReplaceAllString(string(output), "")
		textVideo = strings.ReplaceAll(textVideo, "WEBVTT\nKind: captions\nLanguage: en", "")
		return textVideo, nil
	}
	log.Println("Error trying to match regex: ")
	return "", err
}
