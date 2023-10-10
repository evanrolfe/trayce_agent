package main

import (
	"github.com/evanrolfe/dockerdog/test/support"
)

func main() {
	support.StartMockServer(4122, 4123, "/app/test/support")
}
