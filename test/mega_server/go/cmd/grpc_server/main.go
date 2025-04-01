package main

import (
	"fmt"
	"log"
	"net"

	"github.com/evanrolfe/mock_server/api"
	"google.golang.org/grpc"
)

const grpcPort = 50051

func main() {
	var grpcHandler *GRPCHandler

	// Start GRPC server
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", grpcPort))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcHandler = NewGRPCHandler()
	grpcServer := grpc.NewServer()
	api.RegisterTrayceAgentServer(grpcServer, grpcHandler)

	// Callback
	grpcHandler.SetCallback(func(input *api.Flows) {
		for _, flow := range input.Flows {
			if flow.Request != nil {
				fmt.Println("Received request")
			}

			if flow.Response != nil {
				fmt.Println("Received response")
			}
		}
	})

	// Server
	fmt.Println("Starting GRPC server on port", grpcPort)
	err = grpcServer.Serve(lis)
	if err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
