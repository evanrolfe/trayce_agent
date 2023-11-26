package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

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
	http.HandleFunc("/chunked", serverHandlerChunked)
	http.HandleFunc("/chunked/{n:[0-9]+}", serverHandlerChunked)

	// HTTP server
	go func() {
		fmt.Println("Starting HTTP server on port", httpPort)
		err := http.ListenAndServe(fmt.Sprintf(":%d", httpPort), nil)
		if err != nil {
			log.Fatal("ListenAndServe: ", err)
		}
	}()

	// HTTPS server
	crtPath := filepath.Join(keyDir, crtFile)
	keyPath := filepath.Join(keyDir, keyFile)

	fmt.Println("Starting HTTPS server on port", httpsPort)
	err := http.ListenAndServeTLS(fmt.Sprintf("127.0.0.1:%d", httpsPort), crtPath, keyPath, nil)
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
	StartMockServer(4122, 4123, "/app/test/support")
}
