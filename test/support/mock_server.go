package support

import (
	"fmt"
	"log"
	"net/http"
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

func StartMockServer(port int, keyDir string) {
	http.HandleFunc("/", serverHandler)
	http.HandleFunc("/chunked", serverHandlerChunked)

	crtPath := filepath.Join(keyDir, crtFile)
	keyPath := filepath.Join(keyDir, keyFile)

	err := http.ListenAndServeTLS(":4123", crtPath, keyPath, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

// GET /
// returns a normal response (with Content-Length header)
func serverHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")

	w.Write([]byte("Hello world.\n"))
}

// GET /chunked
// returns a chunked response (with "Transfer-Encoding: chunked" header)
func serverHandlerChunked(w http.ResponseWriter, req *http.Request) {
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
