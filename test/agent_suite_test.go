package test

import (
	"fmt"
	"log"
	"net"
	"os"
	"testing"

	"github.com/evanrolfe/trayce_agent/api"
	"github.com/evanrolfe/trayce_agent/test/support"
	"google.golang.org/grpc"
)

var grpcHandler *support.GRPCHandler

func TestMain(m *testing.M) {
	// Start GRPC server
	lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", grpcPort))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcHandler = support.NewGRPCHandler()
	grpcServer := grpc.NewServer()
	api.RegisterTrayceAgentServer(grpcServer, grpcHandler)

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
