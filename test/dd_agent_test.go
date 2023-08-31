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
	grpcPort          = 50051
	requestRubyScript = "/app/test/scripts/request_ruby"
)

func TestMain(m *testing.M) {
	fmt.Println("SETUP!")
	// call flag.Parse() here if TestMain uses flags
	code := m.Run()
	fmt.Println("Teardown!")
	os.Exit(code)
}

func Test_dd_agent(t *testing.T) {
	// TODO: Make this handle https
	// // Create a new HTTP request handler
	// handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 	w.WriteHeader(http.StatusOK)
	// 	fmt.Fprintf(w, "Hello, world!")
	// })

	// // Create a test HTTP server using httptest
	// server := httptest.NewServer(handler)
	// defer server.Close()

	// Start GRPC server
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", grpcPort))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcHandler := support.NewGRPCHandler()
	grpcServer := grpc.NewServer()
	api.RegisterDockerDogAgentServer(grpcServer, grpcHandler)

	go func() {
		err = grpcServer.Serve(lis)
		if err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()
	log.Printf("server listening at %v", lis.Addr())

	// Start dd_agent
	cmd := exec.Command("/app/dd_agent")

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	cmd.Start()

	// TODO: This should wait for a request lfrom the client like "dd_agent_started"
	time.Sleep(2 * time.Second)

	// Run tests
	tests := []struct {
		name string
	}{
		{
			name: "an HTTPS request with ruby",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a context with a timeout
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			var requests []*api.RequestObserved
			grpcHandler.SetCallback(func(input *api.RequestObserved) {
				requests = append(requests, input)

				if len(requests) == 2 {
					cancel()
				}
			})

			reqCmd := exec.Command(requestRubyScript, "https://www.pntest.io")
			reqCmd.Start()
			fmt.Println("dd_agent started, request started, waiting to hear back from dd_agent...")

			// Wait for the context to complete
			<-ctx.Done()

			// fmt.Println("-------------------------------------------------------------------------")
			// fmt.Println(stdoutBuf.String())
			// fmt.Println(stderrBuf.String())

			assert.Equal(t, 2, len(requests))

			assert.Greater(t, len(requests[0].RemoteAddr), 0)
			assert.Equal(t, "GET / HTTP/1.1", string(requests[0].Request[0:14]))
			assert.Empty(t, requests[0].Response)

			assert.Greater(t, len(requests[1].RemoteAddr), 0)
			assert.Equal(t, "GET / HTTP/1.1", string(requests[1].Request[0:14]))
			assert.Equal(t, "HTTP/1.1 301 Moved Permanently", string(requests[1].Response[0:30]))
		})
	}
}
