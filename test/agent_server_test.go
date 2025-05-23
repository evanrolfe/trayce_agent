package test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/evanrolfe/trayce_agent/api"
	"github.com/stretchr/testify/assert"
)

const (
	mockHttpPort  = 4122
	mockHttpsPort = 4123
	grpcPort      = 50051
)

// Test_agent_client tests requests made from this container to another server, it listens to the server
func Test_agent_server(t *testing.T) {
	// Handle command line args
	startAgentFlg := os.Getenv("START_AGENT")
	startAgent := true
	if startAgentFlg == "false" {
		startAgent = false
	}

	licenseKey := os.Getenv("TRAYCE_LICENSE_KEY")
	if licenseKey == "" {
		fmt.Println("Warning: TRAYCE_LICENSE_KEY is not set")
	}

	// Find the mega_server container
	megaserverId, megaserverIp := getMegaServer(t)
	numRequests, expectedNumFlows, timeout := getTestConfig()

	// Intercept it
	grpcHandler.SetContainerIds([]string{megaserverId})
	grpcHandler.SetLicenseKey(licenseKey)

	// Start trayce_agent
	var trayceAgent *exec.Cmd
	var stdoutBuf, stderrBuf bytes.Buffer
	if startAgent {
		trayceAgent = exec.Command("/app/trayce_agent")
		trayceAgent.Stdout = &stdoutBuf
		trayceAgent.Stderr = &stderrBuf
	}

	// Wait for trayce_agent to start, timeout of 5secs:
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	grpcHandler.SetAgentStartedCallback(func(input *api.AgentStarted) { cancel() })

	// Trigger the command and then wait for the context to complete
	if startAgent {
		trayceAgent.Start()
		fmt.Println("Started trayce_agent")
	}
	<-ctx.Done()
	time.Sleep(2000 * time.Millisecond)

	// Run tests
	// Set focus: true in order to only run a single test case
	tests := []struct {
		name        string
		cmd         *exec.Cmd
		url         string
		numRequests int
		multiplier  int
		http2       bool
		focus       bool
		loadtest    bool
		verify      func(t *testing.T, requests []*api.Flow)
	}{
		{
			name:        "[Python] Server an HTTP/1.1 request",
			url:         fmt.Sprintf("http://%s:%d/", megaserverIp, 3001),
			numRequests: numRequests,
			http2:       false,
			verify:      AssertFlows,
			loadtest:    true,
		},
		{
			name:        "[Python] Server an HTTPS/1.1 request",
			url:         fmt.Sprintf("https://%s:%d/", megaserverIp, 3002),
			numRequests: numRequests,
			http2:       false,
			verify:      AssertFlows,
		},
		{
			name:        "[Python] Server an HTTPS/1.1 request to /second_https",
			url:         fmt.Sprintf("https://%s:%d/second_http", megaserverIp, 3002),
			numRequests: numRequests,
			http2:       false,
			verify:      AssertFlows,
			multiplier:  2,
		},
		{
			name:        "[Python] Server an HTTP/1.1 request to /large",
			url:         fmt.Sprintf("http://%s:%d/large", megaserverIp, 3001),
			numRequests: numRequests,
			http2:       false,
			verify:      AssertFlows,
		},
		{
			name:        "[Python] Server an HTTPS/1.1 request to /large",
			url:         fmt.Sprintf("https://%s:%d/large", megaserverIp, 3002),
			numRequests: numRequests,
			http2:       false,
			verify:      AssertFlows,
		},
		{
			name:        "[Python] Server an HTTP/1.1 request to /second_http",
			url:         fmt.Sprintf("http://%s:%d/second_http", megaserverIp, 3001),
			numRequests: numRequests,
			http2:       false,
			verify:      AssertFlows,
			multiplier:  2,
			loadtest:    true,
		},
		{
			name:        "[Ruby] Server an HTTP/1.1 request",
			url:         fmt.Sprintf("http://%s:%d/", megaserverIp, 3003),
			numRequests: numRequests,
			http2:       false,
			verify:      AssertFlows,
		},
		{
			name:        "[Ruby] Server an HTTP/1.1 request to /second_http",
			url:         fmt.Sprintf("http://%s:%d/second_http", megaserverIp, 3003),
			numRequests: numRequests,
			http2:       false,
			verify:      AssertFlows,
			multiplier:  2,
		},
		{
			name:        "[Ruby] Server an HTTPS/1.1 request",
			url:         fmt.Sprintf("https://%s:%d/", megaserverIp, 3004),
			numRequests: numRequests,
			http2:       false,
			verify:      AssertFlows,
		},
		{
			name:        "[Ruby] Server an HTTPS/1.1 request to /second_https",
			url:         fmt.Sprintf("https://%s:%d/second_https", megaserverIp, 3004),
			numRequests: numRequests,
			http2:       false,
			multiplier:  2,
			verify:      AssertFlows,
			loadtest:    true,
		},
		{
			name:        "[Ruby] Server an HTTP/1.1 request to /large",
			url:         fmt.Sprintf("http://%s:%d/large", megaserverIp, 3003),
			numRequests: numRequests,
			http2:       false,
			verify:      AssertFlows,
		},
		{
			name:        "[Ruby] Server an HTTPS/1.1 request to /large",
			url:         fmt.Sprintf("https://%s:%d/large", megaserverIp, 3004),
			numRequests: numRequests,
			http2:       false,
			verify:      AssertFlows,
		},
		{
			name:        "[Go] Server an HTTP/1.1 request",
			url:         fmt.Sprintf("http://%s:%d/", megaserverIp, 4122),
			numRequests: numRequests,
			http2:       false,
			verify:      AssertFlows,
		},
		{
			name:        "[Go] Server an HTTPS/1.1 request",
			url:         fmt.Sprintf("https://%s:%d/", megaserverIp, 4123),
			numRequests: numRequests,
			http2:       false,
			verify:      AssertFlows,
		},
		{
			name:        "[Go] Server an HTTP/1.1 request to /second_http",
			url:         fmt.Sprintf("http://%s:%d/second_http", megaserverIp, 4122),
			numRequests: numRequests,
			http2:       false,
			verify:      AssertFlows,
			multiplier:  2,
			loadtest:    true,
		},
		{
			name:        "[Go] Server an HTTP/1.1 request to /second_http",
			url:         fmt.Sprintf("http://%s:%d/second_http", megaserverIp, 4122),
			numRequests: numRequests,
			http2:       false,
			multiplier:  2,
			verify:      AssertFlows,
		},
		{
			name:        "[Go] Server an HTTPS/1.1 request to /large",
			url:         fmt.Sprintf("https://%s:%d/large", megaserverIp, 4123),
			numRequests: numRequests,
			http2:       false,
			verify:      AssertFlows,
		},
		{
			name:        "[Go] Server an HTTP/1.1 request to /large",
			url:         fmt.Sprintf("http://%s:%d/large", megaserverIp, 4122),
			numRequests: numRequests,
			http2:       false,
			verify:      AssertFlows,
		},
		{
			name:        "[Go] Server an HTTPS/2 request",
			url:         fmt.Sprintf("https://%s:%d/", megaserverIp, 4123),
			numRequests: numRequests,
			http2:       true,
			verify:      AssertFlowsHttp2,
			loadtest:    true,
		},
		{
			name:        "[Go] Server an HTTPS/2 request to /second_http",
			url:         fmt.Sprintf("https://%s:%d/second_http", megaserverIp, 4123),
			numRequests: numRequests,
			http2:       true,
			verify:      func(t *testing.T, requests []*api.Flow) {},
			multiplier:  2,
			loadtest:    true,
		},
		{
			name:        "[Go] Server a GRPC message",
			url:         fmt.Sprintf("grpc://%s:%d", megaserverIp, 50051),
			numRequests: numRequests,
			http2:       true,
			verify:      func(t *testing.T, requests []*api.Flow) {},
			loadtest:    false,
		},
		{
			name:        "[Postgres] SELECT query",
			url:         fmt.Sprintf("psql://%s:%d", megaserverIp, 5432),
			numRequests: numRequests,
			verify:      func(t *testing.T, requests []*api.Flow) {},
			loadtest:    false,
		},
		{
			name:        "[Postgres] SELECT query via Go",
			url:         fmt.Sprintf("http://%s:%d/psql_select", megaserverIp, 4122),
			numRequests: numRequests,
			verify:      func(t *testing.T, requests []*api.Flow) {},
			multiplier:  2,
		},
		{
			name:        "[Postgres] SELECT prepared query via Go",
			url:         fmt.Sprintf("http://%s:%d/psql_select_prep", megaserverIp, 4122),
			numRequests: numRequests,
			verify:      func(t *testing.T, requests []*api.Flow) {},
			multiplier:  2,
		},
		// {
		// 	name:        "[Postgres] transaction via Go",
		// 	url:         fmt.Sprintf("http://%s:%d/psql_transaction", megaserverIp, 4122),
		// 	numRequests: numRequests,
		// 	verify:      func(t *testing.T, requests []*api.Flow) {},
		// 	multiplier:  2,
		// 	focus:       true,
		// },
		{
			name:        "[MySQL] SELECT query",
			url:         fmt.Sprintf("mysql://%s:%d", megaserverIp, 3306),
			numRequests: numRequests,
			verify:      func(t *testing.T, requests []*api.Flow) {},
			loadtest:    false,
		},
		{
			name:        "[MySQL] SELECT query via Go",
			url:         fmt.Sprintf("http://%s:%d/mysql_select", megaserverIp, 4122),
			numRequests: numRequests,
			verify:      func(t *testing.T, requests []*api.Flow) {},
			multiplier:  2,
		},
		{
			name:        "[MySQL] SELECT prepared query via Go",
			url:         fmt.Sprintf("http://%s:%d/mysql_select_prep", megaserverIp, 4122),
			numRequests: numRequests,
			verify:      func(t *testing.T, requests []*api.Flow) {},
			multiplier:  2,
		},
		{
			name:        "[MySQL] transaction via Go",
			url:         fmt.Sprintf("http://%s:%d/mysql_transaction", megaserverIp, 4122),
			numRequests: numRequests,
			verify:      func(t *testing.T, requests []*api.Flow) {},
			multiplier:  3,
		},
		// TODO: Support NodeJS
		// {
		// 	name:   "[Node] Server an HTTPS/1.1 request",
		// 	focus:  true,
		// 	cmd:    exec.Command(requestRubyScriptHttpLoad, fmt.Sprintf("https://%s:%d/", megaserverIp, 3003), strconv.Itoa(numRequests)),
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
		if !testing.Short() && !tt.loadtest {
			continue
		}

		t.Run(tt.name, func(t *testing.T) {
			// Create a context with a timeout
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			multiplier := tt.multiplier
			if multiplier == 0 {
				multiplier = 1
			}
			// Wait until we receive 2 messages (one for the request and one for the response) from GRPC
			flows := []*api.Flow{}
			grpcHandler.SetCallback(func(input *api.Flows) {
				flows = append(flows, input.Flows...)
				if len(flows)%100 == 0 {
					fmt.Println("Received", len(flows))
				}
				if len(flows) >= expectedNumFlows*multiplier {
					cancel()
				}
			})

			time.Sleep(250 * time.Millisecond)
			// Make the request
			makeRequests(tt.url, tt.http2, numRequests)
			// Wait for the context to complete
			<-ctx.Done()

			if !testing.Short() {
				// This is necessary in a loadtest incase more than the expected num flows are sent
				time.Sleep(2 * time.Second)
			}

			//
			// OUTPUT [uncomment this to log the output to file or screen]
			//
			// err := os.WriteFile("/app/tmp/test_output.txt", stdoutBuf.Bytes(), 0644)
			// if err != nil {
			// 	fmt.Println("Error writing to file:", err)
			// }
			fmt.Println(stdoutBuf.String())

			// Verify the result
			assert.Equal(t, expectedNumFlows*multiplier, len(flows))
			// for _, flow := range flows {
			// 	fmt.Println("Req:", flow.Request)
			// }
			tt.verify(t, flows)
			fmt.Printf("================================================\nCompleted %d/%d\n================================================\n", i, len(tests))

			// checkForDuplicates(flows)
		})
	}

	if startAgent {
		trayceAgent.Process.Signal(syscall.SIGTERM)
	}
}

// func checkForDuplicates(flows []*api.Flow) {
// 	requestIDsMap := map[string][]string{}
// 	for _, flow := range flows {
// 		if flow.Request != nil {
// 			requestID := extractRequestID(flow.Request)
// 			x := requestIDsMap[requestID]

// 			uuidStr := "req-" + flow.Uuid
// 			if x == nil {
// 				requestIDsMap[requestID] = []string{uuidStr}
// 			} else {
// 				requestIDsMap[requestID] = append(requestIDsMap[requestID], uuidStr)
// 			}
// 		}

// 		if len(flow.ResponseRaw) > 0 {
// 			requestID := extractRequestID(flow.ResponseRaw)
// 			x := requestIDsMap[requestID]

// 			uuidStr := "resp-" + flow.Uuid
// 			if x == nil {
// 				requestIDsMap[requestID] = []string{uuidStr}
// 			} else {
// 				requestIDsMap[requestID] = append(requestIDsMap[requestID], uuidStr)
// 			}
// 		}
// 	}

// 	for requestID, uuids := range requestIDsMap {
// 		if len(uuids) != 2 {
// 			fmt.Println("X-Request-ID:", requestID, "=>", uuids)
// 		}
// 	}
// }

// func extractRequestID(data []byte) string {
// 	scanner := bufio.NewScanner(bytes.NewReader(data))
// 	requestID := ""

// 	for scanner.Scan() {
// 		line := scanner.Text()
// 		if strings.HasPrefix(line, "X-Request-Id:") {
// 			// Extract the X-Request-ID
// 			requestID = strings.TrimSpace(strings.TrimPrefix(line, "X-Request-Id:"))
// 			break
// 		} else if strings.HasPrefix(line, "x-request-id:") {
// 			// Extract the X-Request-ID
// 			requestID = strings.TrimSpace(strings.TrimPrefix(line, "x-request-id:"))
// 			break
// 		}
// 	}

// 	// if requestID == "" {
// 	// 	fmt.Println("------------ NO requestID:\n", string(data))
// 	// }

// 	return requestID
// }
