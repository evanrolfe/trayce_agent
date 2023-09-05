package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/evanrolfe/dockerdog/api"
	"github.com/evanrolfe/dockerdog/test/support"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

const (
	mockHttpPort          = 4122
	mockHttpsPort         = 4123
	grpcPort              = 50051
	requestRubyScript     = "/app/test/scripts/request_ruby"
	requestRubyScriptHttp = "/app/test/scripts/request_ruby_http"
)

var grpcHandler *support.GRPCHandler

func TestMain(m *testing.M) {
	// Setup

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

func Test_dd_agent(t *testing.T) {
	// Start dd_agent
	cmd := exec.Command("/app/dd_agent")

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	// Wait for dd_agent to start, timeout of 5secs:
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
		verify func(requests []*api.FlowObserved)
	}{
		{
			name: "[Ruby] an HTTP/1.1 request",
			cmd:  exec.Command(requestRubyScriptHttp, fmt.Sprintf("http://localhost:%d/", mockHttpPort)),
			verify: func(requests []*api.FlowObserved) {
				assert.Greater(t, len(requests[0].RemoteAddr), 0)
				assert.Equal(t, "GET / HTTP/1.1", string(requests[0].Request[0:14]))
				assert.Empty(t, requests[0].Response)
				assert.Equal(t, "tcp", requests[0].L4Protocol)
				assert.Equal(t, "http", requests[0].L7Protocol)

				assert.Greater(t, len(requests[1].RemoteAddr), 0)
				assert.Equal(t, "GET / HTTP/1.1", string(requests[1].Request[0:14]))
				assert.Equal(t, "HTTP/1.1 200 OK", string(requests[1].Response[0:15]))
				assert.Equal(t, "tcp", requests[1].L4Protocol)
				assert.Equal(t, "http", requests[1].L7Protocol)
			},
		},
		{
			name: "[Ruby] an HTTP/1.1 request with a chunked response",
			cmd:  exec.Command(requestRubyScriptHttp, fmt.Sprintf("http://localhost:%d/chunked", mockHttpPort)),
			verify: func(requests []*api.FlowObserved) {
				assert.Greater(t, len(requests[0].RemoteAddr), 0)
				assert.Equal(t, "GET /chunked HTTP/1.1", string(requests[0].Request[0:21]))
				assert.Empty(t, requests[0].Response)
				assert.Equal(t, "tcp", requests[0].L4Protocol)
				assert.Equal(t, "http", requests[0].L7Protocol)

				assert.Greater(t, len(requests[1].RemoteAddr), 0)
				assert.Equal(t, "GET /chunked HTTP/1.1", string(requests[1].Request[0:21]))
				assert.Equal(t, "HTTP/1.1 200 OK", string(requests[1].Response[0:15]))
				assert.Equal(t, "tcp", requests[1].L4Protocol)
				assert.Equal(t, "http", requests[1].L7Protocol)
			},
		},
		{
			name: "[Ruby] an HTTPS/1.1 request",
			cmd:  exec.Command(requestRubyScript, fmt.Sprintf("https://localhost:%d/", mockHttpsPort)),
			verify: func(requests []*api.FlowObserved) {
				assert.Greater(t, len(requests[0].RemoteAddr), 0)
				assert.Equal(t, "GET / HTTP/1.1", string(requests[0].Request[0:14]))
				assert.Empty(t, requests[0].Response)
				assert.Equal(t, "tcp", requests[0].L4Protocol)
				assert.Equal(t, "http", requests[0].L7Protocol)

				assert.Greater(t, len(requests[1].RemoteAddr), 0)
				assert.Equal(t, "GET / HTTP/1.1", string(requests[1].Request[0:14]))
				assert.Equal(t, "HTTP/1.1 200 OK", string(requests[1].Response[0:15]))
				assert.Equal(t, "tcp", requests[1].L4Protocol)
				assert.Equal(t, "http", requests[1].L7Protocol)
			},
		},
		{
			name: "[Ruby] an HTTPS/1.1 request with a chunked response",
			cmd:  exec.Command(requestRubyScript, fmt.Sprintf("https://localhost:%d/chunked", mockHttpsPort)),
			verify: func(requests []*api.FlowObserved) {
				assert.Greater(t, len(requests[0].RemoteAddr), 0)
				assert.Equal(t, "GET /chunked HTTP/1.1", string(requests[0].Request[0:21]))
				assert.Empty(t, requests[0].Response)
				assert.Equal(t, "tcp", requests[0].L4Protocol)
				assert.Equal(t, "http", requests[0].L7Protocol)

				assert.Greater(t, len(requests[1].RemoteAddr), 0)
				assert.Equal(t, "GET /chunked HTTP/1.1", string(requests[1].Request[0:21]))
				assert.Equal(t, "HTTP/1.1 200 OK", string(requests[1].Response[0:15]))
				assert.Equal(t, "tcp", requests[1].L4Protocol)
				assert.Equal(t, "http", requests[1].L7Protocol)
			},
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
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			// Wait until we receive 2 messages (one for the request and one for the response) from GRPC
			var requests []*api.FlowObserved
			grpcHandler.SetCallback(func(input *api.FlowObserved) {
				requests = append(requests, input)

				if len(requests) == 2 {
					cancel()
				}
			})

			// Make the request
			tt.cmd.Start()

			// Wait for the context to complete
			<-ctx.Done()

			// fmt.Println("-------------------------------------------------------------------------")
			// fmt.Println(stdoutBuf.String())
			// fmt.Println("-------------------------------------------------------------------------")
			// fmt.Println(stderrBuf.String())

			// Verify the result
			assert.Equal(t, 2, len(requests))
			tt.verify(requests)
		})
	}
}
