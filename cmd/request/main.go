package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"
)

// go build -o test/scripts/go_request -buildvcs=false ./cmd/request/

func makeRequest(url string, i int) {
	_, err := http.Get(fmt.Sprintf("%s/%v", url, i))

	if err != nil {
		fmt.Printf("error making http request: %s\n", err)
		os.Exit(1)
	}

	// fmt.Printf("response status code: %d\n", res.StatusCode)
}

func main() {
	url := os.Args[1]
	nStr := os.Args[2]

	n, err := strconv.Atoi(nStr)
	if err != nil {
		panic(fmt.Sprintf("cannot parse int: %s", nStr))
	}

	// Because Go is so much faster than python/ruby/node, we need to add this sleep here to ensure that the agent picks up
	// this new process in the container which is refreshed every 5ms
	time.Sleep(50 * time.Millisecond)

	for i := 0; i < n; i++ {
		makeRequest(url, i)
		// time.Sleep(5 * time.Millisecond)
	}
}
