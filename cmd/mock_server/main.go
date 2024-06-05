package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

// Build:
// go build -o test/mega_server/go -buildvcs=false -gcflags "all=-N -l" ./cmd/mock_server/

// Generate key pair with:
//
// openssl genrsa -out server.key 2048
// openssl ecparam -genkey -name secp384r1 -out server.key
// openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650
const (
	crtFile = "server.crt"
	keyFile = "server.key"
)

func makeRequest() {
	url := "http://www.pntest.io"
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		// CheckRedirect: func(req *http.Request, via []*http.Request) error {
		// 	return http.ErrUseLastResponse
		// },
	}

	req, err := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept-Encoding", "identity")
	res, err := client.Do(req)

	if err != nil {
		fmt.Printf("error making http request: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("response status code: %d\n", res.StatusCode)

	// body, _ := io.ReadAll(res.Body)
	// fmt.Println(string(body))

}

func StartMockServer(httpPort int, httpsPort int, keyDir string) {
	// Handlers
	http.HandleFunc("/", serverHandler)
	http.HandleFunc("/large", serverHandlerLarge)
	http.HandleFunc("/chunked", serverHandlerChunked)
	http.HandleFunc("/chunked/{n:[0-9]+}", serverHandlerChunked)

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
	// makeRequest()
	w.Header().Set("Content-Type", "text/plain")

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

func main() {
	StartMockServer(4122, 4123, ".")
}
