package test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/evanrolfe/trayce_agent/api"
	"github.com/stretchr/testify/assert"
)

// Test_agent_client tests requests made from this container to another server, it listens to the server
func Test_agent_server(t *testing.T) {
	// Find the mega_server container
	megaserverId, megaserverIp := getMegaServer(t)
	numRequests, expectedNumFlows, timeout := getTestConfig()

	// Intercept it
	grpcHandler.SetContainerIds([]string{megaserverId})

	// Start trayce_agent
	trayceAgent := exec.Command("/app/trayce_agent")

	var stdoutBuf, stderrBuf bytes.Buffer
	trayceAgent.Stdout = &stdoutBuf
	trayceAgent.Stderr = &stderrBuf

	// Wait for trayce_agent to start, timeout of 5secs:
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	grpcHandler.SetAgentStartedCallback(func(input *api.AgentStarted) { cancel() })

	// Trigger the command and then wait for the context to complete
	trayceAgent.Start()
	<-ctx.Done()

	// Run tests
	// Set focus: true in order to only run a single test case
	tests := []struct {
		name       string
		cmd        *exec.Cmd
		focus      bool
		multiplier int
		verify     func(t *testing.T, requests []*api.Flow)
	}{
		{
			name:       "[Python] Server an HTTP/1.1 request",
			cmd:        exec.Command(requestGoScript, fmt.Sprintf("http://%s:%d/", megaserverIp, 3001), strconv.Itoa(numRequests), "http1"),
			verify:     AssertFlows,
			multiplier: 1,
		},
		{
			name:       "[Python] Server an HTTPS/1.1 request",
			cmd:        exec.Command(requestGoScript, fmt.Sprintf("https://%s:%d/", megaserverIp, 3002), strconv.Itoa(numRequests), "http1"),
			verify:     AssertFlows,
			multiplier: 1,
		},
		{
			name:       "[Python] Server an HTTPS/1.1 request to /second_https",
			cmd:        exec.Command(requestGoScript, fmt.Sprintf("https://%s:%d/second_http", megaserverIp, 3002), strconv.Itoa(numRequests), "http1"),
			verify:     AssertFlows,
			multiplier: 1,
		},
		{
			name:       "[Ruby] Server an HTTP/1.1 request",
			cmd:        exec.Command(requestGoScript, fmt.Sprintf("http://%s:%d/", megaserverIp, 3003), strconv.Itoa(numRequests), "http1"),
			verify:     AssertFlows,
			multiplier: 1,
		},
		{
			name:       "[Ruby] Server an HTTP/1.1 request to /second_http",
			cmd:        exec.Command(requestGoScript, fmt.Sprintf("http://%s:%d/second_http", megaserverIp, 3003), strconv.Itoa(numRequests), "http1"),
			verify:     AssertFlows,
			multiplier: 1,
		},
		{
			name:       "[Ruby] Server an HTTPS/1.1 request",
			cmd:        exec.Command(requestGoScript, fmt.Sprintf("https://%s:%d/", megaserverIp, 3004), strconv.Itoa(numRequests), "http1"),
			verify:     AssertFlows,
			multiplier: 1,
		},
		{
			name:       "[Ruby] Server an HTTPS/1.1 request to /second_https",
			cmd:        exec.Command(requestGoScript, fmt.Sprintf("https://%s:%d/second_https", megaserverIp, 3004), strconv.Itoa(numRequests), "http1"),
			verify:     AssertFlows,
			multiplier: 1,
		},
		// TODO: Get this working again
		// {
		// 	name:       "[Go] Server an HTTPS/2 request",
		// 	cmd:        exec.Command(requestGoScript, fmt.Sprintf("https://%s:%d/", megaserverIp, 4123), strconv.Itoa(numRequests), "http2"),
		// 	verify:     AssertFlowsHttp2,
		// 	multiplier: 1,
		// 	focus:      true,
		// },
		{
			name:       "[Go] Server an HTTPS/1.1 request",
			cmd:        exec.Command(requestGoScript, fmt.Sprintf("https://%s:%d/", megaserverIp, 4123), strconv.Itoa(numRequests), "http1"),
			verify:     AssertFlows,
			multiplier: 1,
		},
		{
			name:       "[Go] Server an HTTP/1.1 request",
			cmd:        exec.Command(requestGoScript, fmt.Sprintf("http://%s:%d/", megaserverIp, 4122), strconv.Itoa(numRequests), "http1"),
			verify:     AssertFlows,
			multiplier: 1,
		},
		{
			name:       "[Go] Server an HTTP/1.1 request to /second_http",
			cmd:        exec.Command(requestGoScript, fmt.Sprintf("http://%s:%d/second_http", megaserverIp, 4122), strconv.Itoa(numRequests), "http1"),
			verify:     AssertFlows,
			multiplier: 1,
		},
		// {
		// 	name:       "[Go] Server an HTTP/1.1 request to /second",
		// 	cmd:        exec.Command(requestGoScript, fmt.Sprintf("http://%s:%d/second", megaserverIp, 4122), strconv.Itoa(numRequests), "http1"),
		// 	verify:     AssertFlows2,
		// 	multiplier: 2,
		// },
		// {
		// 	name:       "[Go] Server an HTTPS/2 request to /second",
		// 	cmd:        exec.Command(requestGoScript, fmt.Sprintf("https://%s:%d/second", megaserverIp, 4123), strconv.Itoa(numRequests), "http2"),
		// 	verify:     AssertFlows2,
		// 	multiplier: 2,
		// },
		// TODO: Support NodeJS
		// {
		// 	name:   "[Node] Server an HTTPS/1.1 request",
		// 	focus:  true,
		// 	cmd:    exec.Command(requestRubyScriptHttpLoad, fmt.Sprintf("https://%s:%d/", megaserverIp, 3003), strconv.Itoa(numRequests)),
		// 	verify: AssertFlows,
		// },
		// TODO: Support Java
		// {
		// 	name:   "[Java] Server an HTTPS/1.1 request",
		// 	cmd:    exec.Command(requestRubyScriptHttpLoad, fmt.Sprintf("https://%s:%d/", megaserverIp, 3002), strconv.Itoa(numRequests)),
		// 	verify: AssertFlows,
		// },
	}

	hasFocus := false
	for _, tt := range tests {
		if tt.focus {
			hasFocus = true
		}
	}

	for i, tt := range tests {
		if hasFocus && !tt.focus {
			continue
		}

		t.Run(tt.name, func(t *testing.T) {
			// Create a context with a timeout
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			// For some requests i.e. host:4123/second, this also makes another request so we multiply by 2
			expectedNum := expectedNumFlows * tt.multiplier

			// Wait until we receive 2 messages (one for the request and one for the response) from GRPC
			flows := []*api.Flow{}
			grpcHandler.SetCallback(func(input *api.Flows) {
				flows = append(flows, input.Flows...)
				if len(flows)%100 == 0 {
					fmt.Println("Received", len(flows))
				}
				if len(flows) >= expectedNum {
					cancel()
				}
			})

			// Make the request
			time.Sleep(500 * time.Millisecond)
			tt.cmd.Start()

			// Wait for the context to complete
			<-ctx.Done()

			if !testing.Short() {
				// This is necessary in a loadtest incase more than the expected num flows are sent
				time.Sleep(2 * time.Second)
			}

			err := os.WriteFile("/app/tmp/test_output.txt", stdoutBuf.Bytes(), 0644)
			if err != nil {
				fmt.Println("Error writing to file:", err)
				os.Exit(1)
			}

			// Verify the result
			assert.Equal(t, expectedNum, len(flows))
			tt.verify(t, flows)
			fmt.Printf("Completed %d/%d\n", i, len(tests))

			checkForDuplicates(flows)
		})
	}

	trayceAgent.Process.Signal(syscall.SIGTERM)
}

func checkForDuplicates(flows []*api.Flow) {
	requestIDsMap := map[string][]string{}
	for _, flow := range flows {
		if len(flow.Request) > 0 {
			requestID := extractRequestID(flow.Request)
			x := requestIDsMap[requestID]

			uuidStr := "req-" + flow.Uuid
			if x == nil {
				requestIDsMap[requestID] = []string{uuidStr}
			} else {
				requestIDsMap[requestID] = append(requestIDsMap[requestID], uuidStr)
			}
		}

		if len(flow.Response) > 0 {
			requestID := extractRequestID(flow.Response)
			x := requestIDsMap[requestID]

			uuidStr := "resp-" + flow.Uuid
			if x == nil {
				requestIDsMap[requestID] = []string{uuidStr}
			} else {
				requestIDsMap[requestID] = append(requestIDsMap[requestID], uuidStr)
			}
		}
	}

	for requestID, uuids := range requestIDsMap {
		if len(uuids) != 2 {
			fmt.Println("X-Request-ID:", requestID, "=>", uuids)
		}
	}
}

func extractRequestID(data []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	requestID := ""

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "X-Request-Id:") {
			// Extract the X-Request-ID
			requestID = strings.TrimSpace(strings.TrimPrefix(line, "X-Request-Id:"))
			break
		} else if strings.HasPrefix(line, "x-request-id:") {
			// Extract the X-Request-ID
			requestID = strings.TrimSpace(strings.TrimPrefix(line, "x-request-id:"))
			break
		}
	}

	// if requestID == "" {
	// 	fmt.Println("------------ NO requestID:\n", string(data))
	// }

	return requestID
}
