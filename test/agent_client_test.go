package test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/evanrolfe/trayce_agent/api"
	"github.com/stretchr/testify/assert"
)

const (
	mockHttpPort              = 4122
	mockHttpsPort             = 4123
	grpcPort                  = 50051
	requestRubyScriptHttpLoad = "/app/test/scripts/load_test_ruby"
	requestPythonScript       = "/app/test/scripts/request_python"
	requestGoScript           = "/app/test/scripts/go_request"
)

// Test_agent_client tests requests made from this container to another server, it listens to the client
func Test_agent_client(t *testing.T) {
	// Set trayce_agent to track the container this is running from:
	hostname, err := os.Hostname()
	if err != nil {
		panic(err)
	}
	grpcHandler.SetContainerIds([]string{hostname})

	// Find the mega_server container
	_, megaserverIp := getMegaServer(t)
	numRequests, expectedNumFlows, timeout := getTestConfig()

	// Start trayce_agent
	cmd := exec.Command("/app/trayce_agent", "--filtercmd", "/app/test/scripts/")

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	// Wait for trayce_agent to start, timeout of 5secs:
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
			cmd:    exec.Command(requestRubyScriptHttpLoad, fmt.Sprintf("http://%s:%d/", megaserverIp, mockHttpPort), strconv.Itoa(numRequests)),
			verify: AssertFlows,
		},
		{
			name:   "[Ruby] an HTTP/1.1 request with a chunked response",
			cmd:    exec.Command(requestRubyScriptHttpLoad, fmt.Sprintf("http://%s:%d/chunked", megaserverIp, mockHttpPort), strconv.Itoa(numRequests)),
			verify: AssertFlowsChunked,
		},
		{
			name:   "[Ruby] an HTTPS/1.1 request",
			cmd:    exec.Command(requestRubyScriptHttpLoad, fmt.Sprintf("https://%s:%d/", megaserverIp, mockHttpsPort), strconv.Itoa(numRequests)),
			verify: AssertFlows,
		},
		{
			name:   "[Ruby] an HTTPS/1.1 request with a chunked response",
			cmd:    exec.Command(requestRubyScriptHttpLoad, fmt.Sprintf("https://%s:%d/chunked", megaserverIp, mockHttpsPort), strconv.Itoa(numRequests)),
			verify: AssertFlowsChunked,
		},
		{
			name:   "[Python] an HTTP/1.1 request",
			cmd:    exec.Command(requestPythonScript, fmt.Sprintf("http://%s:%d", megaserverIp, mockHttpPort), strconv.Itoa(numRequests)),
			verify: AssertFlows,
		},
		{
			name:   "[Python] an HTTPS/1.1 request",
			cmd:    exec.Command(requestPythonScript, fmt.Sprintf("https://%s:%d", megaserverIp, mockHttpsPort), strconv.Itoa(numRequests)),
			verify: AssertFlows,
		},
		// NOTE: This (load) test sometimes fails because it receives more than 2000 flows
		{
			name:   "[Go] an HTTP/1.1 request",
			cmd:    exec.Command(requestGoScript, fmt.Sprintf("http://%s:%d", megaserverIp, mockHttpPort), strconv.Itoa(numRequests), "http1"),
			verify: AssertFlows,
		},
		// same issue with this one:
		{
			name:   "[Go] an HTTP/1.1 request with a chunked response",
			cmd:    exec.Command(requestGoScript, fmt.Sprintf("http://%s:%d/chunked", megaserverIp, mockHttpPort), strconv.Itoa(numRequests), "http1"),
			verify: AssertFlowsChunked,
		},
		{
			name: "[Go] an HTTPS/1.1 request",
			// focus:  true,
			cmd:    exec.Command(requestGoScript, fmt.Sprintf("https://%s:%d", megaserverIp, mockHttpsPort), strconv.Itoa(numRequests), "http1"),
			verify: AssertFlows,
		},
		{
			name:   "[Go] an HTTPS/1.1 request with a chunked response",
			cmd:    exec.Command(requestGoScript, fmt.Sprintf("https://%s:%d/chunked", megaserverIp, mockHttpsPort), strconv.Itoa(numRequests), "http1"),
			verify: AssertFlowsChunked,
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
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			// Wait until we receive 2 messages (one for the request and one for the response) from GRPC
			var requests []*api.Flow
			grpcHandler.SetCallback(func(input *api.Flows) {
				requests = append(requests, input.Flows...)
				if len(requests)%100 == 0 {
					fmt.Println("Received", len(requests))
				}
				if len(requests) >= expectedNumFlows {
					cancel()
				}
			})

			// time.Sleep(1 * time.Second)
			// Make the request
			tt.cmd.Start()

			// Wait for the context to complete
			<-ctx.Done()

			if testing.Short() {
				fmt.Println("*-------------------------------------------------------------------------* Start:")
				fmt.Println(stdoutBuf.String())
				fmt.Println("*-------------------------------------------------------------------------* End")
			} else {
				// This is necessary in a loadtest incase more than the expected num requests are sent
				time.Sleep(2 * time.Second)
			}

			// Verify the result
			assert.Equal(t, expectedNumFlows, len(requests))
			tt.verify(t, requests)
		})
	}
}
