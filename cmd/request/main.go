package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"
)

// go build -o test/scripts/go_request -buildvcs=false ./cmd/request/

func makeRequest(url string) {
	fmt.Println("Requesting", url)

	res, err := http.Get(url)
	if err != nil {
		fmt.Printf("error making http request: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("response status code: %d\n", res.StatusCode)
}

func main() {
	url := os.Args[1]
	nStr := os.Args[2]

	n, err := strconv.Atoi(nStr)
	if err != nil {
		panic(fmt.Sprintf("cannot parse int: %s", nStr))
	}

	fmt.Println("PID:", os.Getpid())
	time.Sleep(time.Second)

	for i := 0; i < n; i++ {
		makeRequest(url)
		// time.Sleep(5 * time.Millisecond)
	}
}
