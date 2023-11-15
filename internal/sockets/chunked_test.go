package sockets_test

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	chunkedResponse = `00000000  48 54 54 50 2f 31 2e 31  20 32 30 30 20 4f 4b 0d  |HTTP/1.1 200 OK.|
00000010  0a 58 2d 43 6f 6e 74 65  6e 74 2d 54 79 70 65 2d  |.X-Content-Type-|
00000020  4f 70 74 69 6f 6e 73 3a  20 6e 6f 73 6e 69 66 66  |Options: nosniff|
00000030  0d 0a 44 61 74 65 3a 20  4d 6f 6e 2c 20 31 33 20  |..Date: Mon, 13 |
00000040  4e 6f 76 20 32 30 32 33  20 30 37 3a 35 36 3a 31  |Nov 2023 07:56:1|
00000050  38 20 47 4d 54 0d 0a 54  72 61 6e 73 66 65 72 2d  |8 GMT..Transfer-|
00000060  45 6e 63 6f 64 69 6e 67  3a 20 63 68 75 6e 6b 65  |Encoding: chunke|
00000070  64 0d 0a 0d 0a 39 0d 0a  43 68 75 6e 6b 20 23 31  |d....9..Chunk #1|
00000080  0a 0d 0a 39 0d 0a 43 68  75 6e 6b 20 23 32 0a 0d  |...9..Chunk #2..|
00000090  0a 39 0d 0a 43 68 75 6e  6b 20 23 33 0a 0d 0a 39  |.9..Chunk #3...9|
000000a0  0d 0a 43 68 75 6e 6b 20  23 34 0a 0d 0a 39 0d 0a  |..Chunk #4...9..|
000000b0  43 68 75 6e 6b 20 23 35  0a 0d 0a 30 0d 0a 0d 0a  |Chunk #5...0....|`
)

// This is not a real test and we should delete this soon.. just leaving this here to demo how to parse chunked responses
// so that the extra chars like chunk length are not included in the parsed response body
var _ = Describe("SocketMap", func() {
	chunkedRespBytes, _ := hexDumpToBytes(chunkedResponse)

	FContext("parsing a chunked response", Ordered, func() {
		It("the first flow contains an HTTP request", func() {
			resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(chunkedRespBytes)), nil)
			Expect(err).To(BeNil())

			result, err := io.ReadAll(resp.Body)
			Expect(err).To(BeNil())
			fmt.Println("Result:", string(result))

			Expect(string(result)).To(Equal("Chunk #1\nChunk #2\nChunk #3\nChunk #4\nChunk #5\n"))
		})
	})
})
