package test

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/evanrolfe/dockerdog/api"
	"github.com/evanrolfe/dockerdog/test/support"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

const (
	mockHttpPort              = 4122
	mockHttpsPort             = 4123
	grpcPort                  = 50051
	requestRubyScriptHttpLoad = "/app/test/scripts/load_test_ruby"
	requestPythonScript       = "/app/test/scripts/request_python"
	requestGoScript           = "/app/test/scripts/go_request"

	reqRegex      = `^GET /\d* HTTP/1\.1`
	reqChunkRegex = `^GET /chunked/\d+ HTTP/1\.1`

	numRequestsLoad = 1000
)

var grpcHandler *support.GRPCHandler

func TestMain(m *testing.M) {
	// Start HTTP(S) Mock Server
	go support.StartMockServer(mockHttpPort, mockHttpsPort, "./support")

	// Start GRPC server
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", grpcPort))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcHandler = support.NewGRPCHandler()
	grpcServer := grpc.NewServer()
	api.RegisterDockerDogAgentServer(grpcServer, grpcHandler)

	go func() {
		err = grpcServer.Serve(lis)
		if err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()
	log.Printf("GRPC server listening at %v", lis.Addr())

	// Run Tests
	code := m.Run()

	// Teardown

	os.Exit(code)
}

// TODO: Make this verify that it has all the correct requests
// func hasAllFlows(flows []*api.Flow) {
// 	collectedMatches := []int{}

// 	for _, f := range flows {
// 		if f.Request == nil {
// 			continue
// 		}

// 		req := string(f.Request[0:8])
// 		pattern := `GET /(\d+)`
// 		re := regexp.MustCompile(pattern)
// 		matches := re.FindStringSubmatch(req)

// 		if len(matches) >= 2 {
// 			// The number is in the first capture group (index 1)
// 			number := matches[1]
// 			n, _ := strconv.Atoi(number)
// 			collectedMatches = append(collectedMatches, n)
// 		}
// 	}

// 	fmt.Println(collectedMatches)
// }

func AssertFlows(t *testing.T, flows []*api.Flow) {
	for _, flow := range flows {
		assert.Greater(t, len(flows[0].LocalAddr), 0)
		assert.Greater(t, len(flows[0].RemoteAddr), 0)

		if len(flow.Request) > 0 {
			assert.Regexp(t, regexp.MustCompile(reqRegex), string(flows[0].Request))
			assert.Equal(t, "tcp", flows[0].L4Protocol)
			assert.Equal(t, "http", flows[0].L7Protocol)
		} else if len(flow.Response) > 0 {
			assert.Equal(t, "HTTP/1.1 200 OK", string(flows[1].Response[0:15]))
			assert.Equal(t, "tcp", flows[1].L4Protocol)
			assert.Equal(t, "http", flows[1].L7Protocol)
		}
	}
}

func AssertFlowsChunked(t *testing.T, flows []*api.Flow) {
	for _, flow := range flows {
		assert.Greater(t, len(flows[0].LocalAddr), 0)
		assert.Greater(t, len(flows[0].RemoteAddr), 0)

		if len(flow.Request) > 0 {
			assert.Regexp(t, regexp.MustCompile(reqChunkRegex), string(flows[0].Request))
			assert.Equal(t, "tcp", flows[0].L4Protocol)
			assert.Equal(t, "http", flows[0].L7Protocol)
		} else if len(flow.Response) > 0 {
			assert.Equal(t, "HTTP/1.1 200 OK", string(flows[1].Response[0:15]))
			assert.Equal(t, "tcp", flows[1].L4Protocol)
			assert.Equal(t, "http", flows[1].L7Protocol)
		}
	}
}

func Test_dd_agent_single(t *testing.T) {
	// Load test or single test?
	var numRequests int
	if testing.Short() {
		numRequests = 1
	} else {
		numRequests = numRequestsLoad
	}
	expectedNumFlows := numRequests * 2

	// Start dd_agent
	cmd := exec.Command("/app/dd_agent", "--filtercmd", "/app/test/scripts/")

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	// Wait for dd_agent to start, timeout of 5secs:
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	grpcHandler.SetAgentStartedCallback(func(input *api.AgentStarted) { cancel() })

	// Trigger the command and then wait for the context to complete
	cmd.Start()
	<-ctx.Done()

	// Run tests
	// Set focus: true in order to only run a single test case
	tests := []struct {
		name   string
		cmd    *exec.Cmd
		focus  bool
		verify func(t *testing.T, requests []*api.Flow)
	}{
		{
			name:   "[Ruby] an HTTP/1.1 request",
			cmd:    exec.Command(requestRubyScriptHttpLoad, fmt.Sprintf("http://localhost:%d", mockHttpPort), strconv.Itoa(numRequests)),
			verify: AssertFlows,
		},
		{
			name:   "[Ruby] an HTTP/1.1 request with a chunked response",
			cmd:    exec.Command(requestRubyScriptHttpLoad, fmt.Sprintf("http://localhost:%d/chunked", mockHttpPort), strconv.Itoa(numRequests)),
			verify: AssertFlowsChunked,
		},
		{
			name:   "[Ruby] an HTTPS/1.1 request",
			cmd:    exec.Command(requestRubyScriptHttpLoad, fmt.Sprintf("https://localhost:%d", mockHttpsPort), strconv.Itoa(numRequests)),
			verify: AssertFlows,
		},
		{
			name:   "[Ruby] an HTTPS/1.1 request with a chunked response",
			cmd:    exec.Command(requestRubyScriptHttpLoad, fmt.Sprintf("https://localhost:%d/chunked", mockHttpsPort), strconv.Itoa(numRequests)),
			verify: AssertFlowsChunked,
		},
		{
			name:   "[Python] an HTTP/1.1 request",
			cmd:    exec.Command(requestPythonScript, fmt.Sprintf("http://localhost:%d", mockHttpPort), strconv.Itoa(numRequests)),
			verify: AssertFlows,
		},
		{
			name:   "[Python] an HTTPS/1.1 request",
			cmd:    exec.Command(requestPythonScript, fmt.Sprintf("https://localhost:%d", mockHttpsPort), strconv.Itoa(numRequests)),
			verify: AssertFlows,
		},
		{
			name:   "[Go] an HTTP/1.1 request",
			cmd:    exec.Command(requestGoScript, fmt.Sprintf("http://localhost:%d", mockHttpPort), strconv.Itoa(numRequests)),
			verify: AssertFlows,
		},
		{
			name:   "[Go] an HTTPS/1.1 request",
			focus:  true,
			cmd:    exec.Command(requestGoScript, "https://www.synack.com", strconv.Itoa(numRequests)),
			verify: AssertFlows,
		},
	}

	hasFocus := false
	for _, tt := range tests {
		if tt.focus {
			hasFocus = true
		}
	}

	for _, tt := range tests {
		if hasFocus && !tt.focus {
			continue
		}

		t.Run(tt.name, func(t *testing.T) {
			// Create a context with a timeout
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			// Wait until we receive 2 messages (one for the request and one for the response) from GRPC
			var requests []*api.Flow
			grpcHandler.SetCallback(func(input *api.Flows) {
				requests = append(requests, input.Flows...)
				if len(requests)%100 == 0 {
					fmt.Println("Received", len(requests))
				}
				// if len(requests) == expectedNumFlows {
				// 	cancel()
				// }
			})

			// Make the request
			tt.cmd.Start()

			// Wait for the context to complete
			<-ctx.Done()

			// if len(requests) != 2 {
			fmt.Println("*-------------------------------------------------------------------------* Start:")
			fmt.Println(stdoutBuf.String())
			fmt.Println("*-------------------------------------------------------------------------* End")
			// }
			// fmt.Println(stderrBuf.String())

			// Verify the result
			assert.Equal(t, expectedNumFlows, len(requests))
			tt.verify(t, requests)
		})
	}
}
