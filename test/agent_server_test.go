package test

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/evanrolfe/trayce_agent/api"
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
		name   string
		cmd    *exec.Cmd
		focus  bool
		verify func(t *testing.T, requests []*api.Flow)
	}{
		{
			name:   "[Ruby] Server an HTTPS/1.1 request",
			cmd:    exec.Command(requestGoScript, fmt.Sprintf("https://%s:%d/", megaserverIp, 3000), strconv.Itoa(numRequests), "http1"),
			verify: AssertFlows,
		},
		{
			name:   "[Python] Server an HTTPS/1.1 request",
			cmd:    exec.Command(requestGoScript, fmt.Sprintf("https://%s:%d/", megaserverIp, 3001), strconv.Itoa(numRequests), "http1"),
			verify: AssertFlows,
		},
		{
			name:   "[Go] Server an HTTPS/2 request",
			cmd:    exec.Command(requestGoScript, fmt.Sprintf("https://%s:%d/", megaserverIp, 4123), strconv.Itoa(numRequests), "http2"),
			verify: AssertFlows,
		},
		// TODO: Need to update the verification code to handle this endpoint
		// {
		// 	name:   "[Go] Server an HTTPS/2 request to /second",
		// 	cmd:    exec.Command(requestGoScript, fmt.Sprintf("https://%s:%d/second", megaserverIp, 4123), strconv.Itoa(numRequests), "http2"),
		// 	verify: AssertFlows2,
		// },
		{
			name:   "[Go] Server an HTTPS/1.1 request",
			cmd:    exec.Command(requestGoScript, fmt.Sprintf("https://%s:%d/", megaserverIp, 4123), strconv.Itoa(numRequests), "http1"),
			verify: AssertFlows,
		},
		{
			name:   "[Go] Server an HTTP/1.1 request",
			cmd:    exec.Command(requestGoScript, fmt.Sprintf("http://%s:%d/", megaserverIp, 4122), strconv.Itoa(numRequests), "http1"),
			verify: AssertFlows,
		},
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

			// Make the request
			time.Sleep(500 * time.Millisecond)
			tt.cmd.Start()

			// Wait for the context to complete
			<-ctx.Done()

			if !testing.Short() {
				// This is necessary in a loadtest incase more than the expected num requests are sent
				time.Sleep(2 * time.Second)
			}
			trayceAgent.Process.Signal(syscall.SIGTERM)
			time.Sleep(1 * time.Second)

			if testing.Verbose() {
				fmt.Println("*-------------------------------------------------------------------------* Output Start:")
				fmt.Println(stdoutBuf.String())
				fmt.Println("*-------------------------------------------------------------------------* Output End")
			}

			// Verify the result
			tt.verify(t, requests)
		})
	}
}
