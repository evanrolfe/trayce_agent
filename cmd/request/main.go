package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
)

// go build -o test/sripts/go_request -buildvcs=false ./cmd/request/

func makeRequest(num int) {
	uid, _ := uuid.NewRandom()
	url := fmt.Sprintf("http://www.pntest.io/%s", uid.String())

	fmt.Println("Requesting", url)

	res, err := http.Get(url)
	if err != nil {
		fmt.Printf("error making http request: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("response status code: %d\n", res.StatusCode)
}

func main() {
	// url := os.Args[1]
	fmt.Println("PID:", os.Getpid())

	for i := 0; i < 999; i++ {
		makeRequest(420)
		time.Sleep(time.Second)
	}
}
