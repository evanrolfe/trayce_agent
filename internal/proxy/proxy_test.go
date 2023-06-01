package proxy

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"testing"
)

func TestStartProxy(t *testing.T) {
	StartProxy()

	fmt.Println("testing!")

	proxyURL, _ := url.Parse("http://127.0.0.1:8888")
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}
	httpClient := &http.Client{
		Transport: transport,
	}

	req, _ := http.NewRequest("GET", "http://pntest.io", nil)
	req.Header.Add("Accept-Encoding", "identity")
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("---------------> Response:", resp.StatusCode)
}
