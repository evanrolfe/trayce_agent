package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
)

// go build -o test/scripts/go_request -buildvcs=false -gcflags "all=-N -l" ./cmd/request/

// dlv debug ./cmd/request/ --build-flags="-buildvcs=false"
// b /usr/local/go/src/crypto/tls/conn.go:922
// b main.go:31
//
// (gdb) info args
// my = 0xc0000a7ea0
// url = 0x7fad54 "https://www.pntest.io"
// i = 0
// (gdb) x/d 0x0000007b
// 0xc0000a7ea0:	123

// ====
// Use info args, and subtract my - $sp to get 576
// (gdb) x $sp+576
// 0xc000127f38:	123

// ====
// you can also inspect vars i.e.
// (gdb) p my
// $1 = (main.myRequester *) 0xc00010e000
// (gdb) p my.fd
// $2 = 123
// (gdb) p &my.fd
// $3 = (int *) 0xc00010e010
// (gdb) x 0xc00010e010
// 0xc00010e010:	123

// =================================================================================================
// THIS WORKS WITH DLV!!!
//
// (dlv) b /usr/local/go/src/crypto/tls/conn.go:918
// (dlv) c
// (dlv) print c.conn.fd.pfd.Sysfd
// 5
// (dlv) print &c.conn.fd.pfd.Sysfd
// (*int)(c000176290)
// (dlv) regs
// ...
// Rax = 0x000000c0000fc000
// ...
// then subtract 0xc000176290 - 0xc0000fc000 = 0x7A290 (500368)
// 54310
// actually Rsp might not be the right one to use.. TODO investigate further..

// =================================================================================================
// b /usr/local/go/src/crypto/tls/conn.go:1335

type myConn struct {
	fd int
}

type myRequester struct {
	hello string
	fd    int
	conn  myConn
}

func (my *myRequester) makeRequest(url string, i int) {
	// url = fmt.Sprintf("%s/%v", url, i)
	fmt.Println("Requesting", url)

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

	body, _ := io.ReadAll(res.Body)
	fmt.Println(string(body))
}

func main() {
	var url, nStr string
	if len(os.Args) < 3 {
		url = "https://www.synack.com"
		nStr = "1"
	} else {
		url = os.Args[1]
		nStr = os.Args[2]
	}

	n, err := strconv.Atoi(nStr)
	if err != nil {
		panic(fmt.Sprintf("cannot parse int: %s", nStr))
	}

	// Because Go is so much faster than python/ruby/node, we need to add this sleep here to ensure that the agent picks up
	// this new process in the container which is refreshed every 5ms
	time.Sleep(100 * time.Millisecond)
	requester := myRequester{hello: "world", fd: 123, conn: myConn{fd: 333333}}
	for i := 0; i < n; i++ {
		requester.makeRequest(url, i)
		// time.Sleep(5 * time.Millisecond)
	}
}

// func makeRequest(url string, i int, wg *sync.WaitGroup) {
// 	url = fmt.Sprintf("%s/%v", url, i)
// 	fmt.Println("Requesting", url)
// 	_, err := http.Get(url)

// 	if err != nil {
// 		fmt.Printf("error making http request: %s\n", err)
// 		os.Exit(1)
// 	}
// 	wg.Done()
// 	// fmt.Printf("response status code: %d\n", res.StatusCode)
// }

// func main() {
// 	url := os.Args[1]
// 	nStr := os.Args[2]

// 	n, err := strconv.Atoi(nStr)
// 	if err != nil {
// 		panic(fmt.Sprintf("cannot parse int: %s", nStr))
// 	}

// 	// Because Go is so much faster than python/ruby/node, we need to add this sleep here to ensure that the agent picks up
// 	// this new process in the container which is refreshed every 5ms
// 	time.Sleep(100 * time.Millisecond)

// 	var wg sync.WaitGroup

// 	for i := 0; i < n; i++ {
// 		wg.Add(1)
// 		go makeRequest(url, i, &wg)
// 		// time.Sleep(5 * time.Millisecond)
// 	}

// 	wg.Wait()
// }
