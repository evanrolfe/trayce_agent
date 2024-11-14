package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
)

// Build:
// go build -o test/mega_server/go -buildvcs=false -gcflags "all=-N -l" ./cmd/mock_server/

// Generate key pair with:
// '
// openssl genrsa -out server.key 2048
// openssl ecparam -genkey -name secp384r1 -out server.key
// openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650
const (
	crtFile = "server.crt"
	keyFile = "server.key"
)

func makeRequest(url string) {
	client := &http.Client{
		Transport: &http.Transport{
			// This line forces http1.1:
			TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
		},
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("error http.NewRequest: %s\n", err)
	}
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	res, err := client.Do(req)
	if err != nil {
		fmt.Printf("error making http request: %s\n", err)
	}
	fmt.Printf("Response status code: %d\n", res.StatusCode)

	body, _ := io.ReadAll(res.Body)
	fmt.Println("Response body:", string(body))
}

func StartMockServer(httpPort int, httpsPort int, keyDir string) {
	// Handlers
	http.HandleFunc("/", serverHandler)
	http.HandleFunc("/large", serverHandlerLarge)
	http.HandleFunc("/chunked", serverHandlerChunked)
	http.HandleFunc("/chunked/[0-9]+", serverHandlerChunked)
	http.HandleFunc("/second_http", serverHandlerSecondHTTP)
	http.HandleFunc("/second_https", serverHandlerSecondHTTPS)

	// HTTP server
	go func() {
		fmt.Println("Starting HTTP server on port", httpPort)
		err := http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", httpPort), nil)
		if err != nil {
			log.Fatal("ListenAndServe: ", err)
		}
	}()

	// HTTPS server
	crtPath := filepath.Join(keyDir, crtFile)
	keyPath := filepath.Join(keyDir, keyFile)

	fmt.Println("Starting HTTPS server on port", httpsPort)
	err := http.ListenAndServeTLS(fmt.Sprintf("0.0.0.0:%d", httpsPort), crtPath, keyPath, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
	fmt.Println("Started HTTPS server")
}

// GET /
// returns a normal response (with Content-Length header)
func serverHandler(w http.ResponseWriter, req *http.Request) {
	fmt.Println("GET /")

	reqID := req.Header.Get("X-Request-ID")
	// makeRequest()
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("X-Request-ID", reqID)

	w.Write([]byte("Hello world.\n"))
}

// GET /large
// returns a large response (with Content-Length header)
func serverHandlerLarge(w http.ResponseWriter, req *http.Request) {
	fmt.Println("GET /large")
	// makeRequest()
	w.Header().Set("Content-Type", "text/plain")

	responseBody := []byte{}

	for i := 0; i < 1000; i++ {
		part := strconv.Itoa(i) + ", "
		responseBody = append(responseBody, []byte(part)...)
	}
	responseBody = append(responseBody, []byte("\n")...)
	w.Write(responseBody)
}

// GET /chunked
// returns a chunked response (with "Transfer-Encoding: chunked" header)
func serverHandlerChunked(w http.ResponseWriter, req *http.Request) {
	fmt.Println("GET /chunked")

	flusher, ok := w.(http.Flusher)
	if !ok {
		panic("expected http.ResponseWriter to be an http.Flusher")
	}

	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	for i := 1; i <= 5; i++ {
		fmt.Fprintf(w, "Chunk #%d\n", i)
		flusher.Flush() // Trigger "chunked" encoding and send a chunk...
	}
}

// GET /second_http
// makes another request before returning the response
func serverHandlerSecondHTTP(w http.ResponseWriter, req *http.Request) {
	fmt.Println("GET /second")

	reqID := req.Header.Get("X-Request-ID")

	makeRequest("http://trayce.dev")
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("X-Request-ID", reqID)

	w.Write([]byte("Hello world (second request made).\n"))
}

// GET /second_https
// makes another request before returning the response
func serverHandlerSecondHTTPS(w http.ResponseWriter, req *http.Request) {
	fmt.Println("GET /second")

	reqID := req.Header.Get("X-Request-ID")

	makeRequest("https://trayce.dev")
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("X-Request-ID", reqID)

	w.Write([]byte("Hello world (second request made).\n"))
}

func main() {
	StartMockServer(4122, 4123, ".")
}
