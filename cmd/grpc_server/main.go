package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	pb "github.com/evanrolfe/dockerdog/api"
	"google.golang.org/grpc"
)

const (
	port = 50051
)

type Settings struct {
	ContainerIds []string
}

// server is used to implement helloworld.GreeterServer.
type server struct {
	pb.UnimplementedDockerDogAgentServer
}

// SendFlowObserved implements helloworld.GreeterServer
func (s *server) SendFlowObserved(ctx context.Context, in *pb.FlowObserved) (*pb.Reply, error) {
	log.Printf("Request to: %s", in.RemoteAddr)
	return &pb.Reply{Status: "success "}, nil
}

func (s *server) OpenCommandStream(srv pb.DockerDogAgent_OpenCommandStreamServer) error {
	log.Println("start new stream")
	hostname, err := os.Hostname()
	if err != nil {
		panic(err)
	}

	for i := 0; i < 1; i++ {
		command := pb.Command{
			Type:     "set_settings",
			Settings: &pb.Settings{ContainerIds: []string{hostname}},
		}

		if err := srv.Send(&command); err != nil {
			log.Printf("send error %v", err)
		}
		log.Printf("sent new command:", command.Type)
		time.Sleep(time.Second)
	}

	return nil
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
