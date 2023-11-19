package main

import (
	"fmt"
	"log"
	"net"

	"github.com/evanrolfe/dockerdog/api"
	"github.com/evanrolfe/dockerdog/test/support"
	"google.golang.org/grpc"
)

const grpcPort = 50051

func main() {
	var grpcHandler *support.GRPCHandler

	// Start GRPC server
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", grpcPort))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcHandler = support.NewGRPCHandler()
	grpcServer := grpc.NewServer()
	api.RegisterDockerDogAgentServer(grpcServer, grpcHandler)

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
	err = grpcServer.Serve(lis)
	if err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
