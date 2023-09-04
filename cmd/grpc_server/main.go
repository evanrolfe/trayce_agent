package main

import (
	"context"
	"fmt"
	"log"
	"net"

	pb "github.com/evanrolfe/dockerdog/api"
	"google.golang.org/grpc"
)

const (
	port = 50051
)

// server is used to implement helloworld.GreeterServer.
type server struct {
	pb.UnimplementedDockerDogAgentServer
}

// SendFlowObserved implements helloworld.GreeterServer
func (s *server) SendFlowObserved(ctx context.Context, in *pb.FlowObserved) (*pb.Reply, error) {
	log.Printf("Request to: %s", in.RemoteAddr)
	return &pb.Reply{Status: "success "}, nil
}

func main() {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterDockerDogAgentServer(grpcServer, &server{})

	log.Printf("server listening at %v", lis.Addr())
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
