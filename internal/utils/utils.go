package utils

import (
	"fmt"
	"net/http"
)

func TestRequest(url string) {
	client := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return
	}
	defer resp.Body.Close()
}

func CToGoString(c []byte) string {
	n := -1
	for i, b := range c {
		if b == 0 {
			break
		}
		n = i
	}
	return string(c[:n+1])
}

func PrintBytesHex(bytes []byte) {
	for i, b := range bytes {
		if i > 0 {
			fmt.Print(", ")
		}
		fmt.Printf("0x%02X", b)
	}
	fmt.Println()
}
