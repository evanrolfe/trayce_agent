package support

import (
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

func serverHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("Hello world.\n"))
}

func StartMockServer(port int, keyDir string) {
	http.HandleFunc("/", serverHandler)

	crtPath := filepath.Join(keyDir, crtFile)
	keyPath := filepath.Join(keyDir, keyFile)

	err := http.ListenAndServeTLS(":4123", crtPath, keyPath, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
