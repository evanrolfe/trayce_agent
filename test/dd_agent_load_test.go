package test

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/evanrolfe/dockerdog/api"
	"github.com/stretchr/testify/assert"
)

func AssertFlowsLoad(t *testing.T, flows []*api.FlowObserved) {
	// assert.Greater(t, len(flows[0].RemoteAddr), 0)
	// assert.Equal(t, "GET / HTTP/1.1", string(flows[0].Request[0:14]))
	// assert.Empty(t, flows[0].Response)
	assert.Equal(t, "tcp", flows[0].L4Protocol)
	assert.Equal(t, "http", flows[0].L7Protocol)

	// assert.Greater(t, len(flows[1].RemoteAddr), 0)
	// assert.Equal(t, "HTTP/1.1 200 OK", string(flows[1].Response[0:15]))
	// assert.Empty(t, flows[1].Request)
	assert.Equal(t, "tcp", flows[1].L4Protocol)
	assert.Equal(t, "http", flows[1].L7Protocol)
}

func AssertFlowsChunkedLoad(t *testing.T, flows []*api.FlowObserved) {
	assert.Greater(t, len(flows[0].RemoteAddr), 0)
	assert.Equal(t, "GET /chunked HTTP/1.1", string(flows[0].Request[0:21]))
	assert.Equal(t, "tcp", flows[0].L4Protocol)
	assert.Equal(t, "http", flows[0].L7Protocol)

	assert.Greater(t, len(flows[1].RemoteAddr), 0)
	assert.Equal(t, "HTTP/1.1 200 OK", string(flows[1].Response[0:15]))
	assert.Equal(t, "tcp", flows[1].L4Protocol)
	assert.Equal(t, "http", flows[1].L7Protocol)
}

func Test_dd_agent_load(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	// Start dd_agent
	cmd := exec.Command("/app/dd_agent")

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	// Wait for dd_agent to start, timeout of 5secs:
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	grpcHandler.SetAgentStartedCallback(func(input *api.AgentStarted) { cancel() })

	// Trigger the command and then wait for the context to complete
	cmd.Start()
	<-ctx.Done()

	// Run tests
	// Set focus: true in order to only run a single test case
	tests := []struct {
		name     string
		cmd      *exec.Cmd
		focus    bool
		numFlows int
		verify   func(t *testing.T, requests []*api.FlowObserved)
	}{
		{
			name:     "[Ruby] an HTTP/1.1 request",
			cmd:      exec.Command(requestRubyScriptHttpLoad, fmt.Sprintf("http://localhost:%d/", mockHttpPort), "500"),
			numFlows: 1000,
			verify:   AssertFlowsLoad,
		},
		{
			name:     "[Ruby] an HTTP/1.1 request with a chunked response",
			cmd:      exec.Command(requestRubyScriptHttpLoad, fmt.Sprintf("http://localhost:%d/chunked", mockHttpPort), "500"),
			numFlows: 1000,
			verify:   AssertFlowsChunkedLoad,
		},
		{
			name:     "[Ruby] an HTTPS/1.1 request",
			cmd:      exec.Command(requestRubyScriptHttpLoad, fmt.Sprintf("https://localhost:%d/", mockHttpsPort), "500"),
			numFlows: 1000,
			verify:   AssertFlowsLoad,
		},
		{
			name:     "[Ruby] an HTTPS/1.1 request with a chunked response",
			cmd:      exec.Command(requestRubyScriptHttpLoad, fmt.Sprintf("https://localhost:%d/chunked", mockHttpsPort), "500"),
			numFlows: 1000,
			verify:   AssertFlowsChunkedLoad,
		},
		{
			name:     "[Python] an HTTP/1.1 request",
			cmd:      exec.Command(requestPythonScript, fmt.Sprintf("http://localhost:%d/", mockHttpPort), "500"),
			numFlows: 1000,
			verify:   AssertFlowsLoad,
		},
		{
			name:     "[Python] an HTTPS/1.1 request",
			cmd:      exec.Command(requestPythonScript, fmt.Sprintf("https://localhost:%d/", mockHttpsPort), "500"),
			numFlows: 1000,
			verify:   AssertFlowsLoad,
		},
		// {
		// 	name:   "[Go] an HTTP/1.1 request",
		// 	focus:  true,
		// 	cmd:    exec.Command(requestGoScript, fmt.Sprintf("http://localhost:%d/", mockHttpPort)),
		// 	verify: AssertFlowsLoad,
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
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Wait until we receive 2 messages (one for the request and one for the response) from GRPC
			var requests []*api.FlowObserved
			grpcHandler.SetCallback(func(input *api.FlowObserved) {
				requests = append(requests, input)

				if len(requests) == tt.numFlows {
					cancel()
				}
			})

			// Make the request
			tt.cmd.Start()

			// Wait for the context to complete
			<-ctx.Done()

			// if len(requests) != 2 {
			// fmt.Println("*-------------------------------------------------------------------------* Start:")
			// fmt.Println(stdoutBuf.String())
			// fmt.Println("*-------------------------------------------------------------------------* End")
			// }

			// Verify the result
			assert.Equal(t, tt.numFlows, len(requests))
			tt.verify(t, requests)
		})
	}
}
