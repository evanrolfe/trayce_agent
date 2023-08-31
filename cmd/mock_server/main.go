package main

import (
	"fmt"

	"github.com/evanrolfe/dockerdog/test/support"
)

func main() {
	fmt.Println("Starting mock server on port 4123")
	support.StartMockServer(4123, "/app/test/support")
}
