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

	pb "github.com/evanrolfe/dockerdog/api"
	"google.golang.org/grpc"
)

const (
	port = 50051
)

type testServer struct {
	pb.UnimplementedDockerDogAgentServer
	callback func(input *pb.RequestObserved)
}

func NewTestServer() *testServer {
	return &testServer{
		callback: func(input *pb.RequestObserved) {},
	}
}

func (ts *testServer) SetCallback(callback func(input *pb.RequestObserved)) {
	ts.callback = callback
}

// SendRequestObserved implements helloworld.GreeterServer
func (ts *testServer) SendRequestObserved(ctx context.Context, input *pb.RequestObserved) (*pb.Reply, error) {
	log.Printf("Request: %s %s", input.Method, input.Url)
	ts.callback(input)
	return &pb.Reply{Status: "success "}, nil
}

func TestMain(m *testing.M) {
	fmt.Println("SETUP!")
	// call flag.Parse() here if TestMain uses flags
	code := m.Run()
	fmt.Println("Teardown!")
	os.Exit(code)
}

func Test_dd_agent(t *testing.T) {
	// Start GRPC server
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	testServ := NewTestServer()
	grpcServer := grpc.NewServer()
	pb.RegisterDockerDogAgentServer(grpcServer, testServ)

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

	// fmt.Println(stdoutBuf.String())
	// fmt.Println(stderrBuf.String())

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

			var inputResult *pb.RequestObserved
			testServ.SetCallback(func(input *pb.RequestObserved) {
				fmt.Println("Callback has been triggered!")
				inputResult = input
				cancel()
			})

			reqCmd := exec.Command("ruby", "/app/tmp/request.rb")
			reqCmd.Start()
			fmt.Println("dd_agent started, request started, waiting to hear back from dd_agent...")

			// Wait for the context to complete
			<-ctx.Done()

			if inputResult == nil {
				t.Errorf("no inputResult received!")
				return
			}

			// fmt.Println("RESULT:", inputResult.Method, inputResult.Url)
			// if inputResult.Url != "104.21.63.103:443" {
			// 	t.Errorf("inputResult.Url  expected: %s, actual: %s", "104.21.63.103:443", inputResult.Url)
			// }
		})
	}
}
