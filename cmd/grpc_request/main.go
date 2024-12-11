package main

import (
	"context"
	"fmt"
	"os"

	"github.com/evanrolfe/trayce_agent/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	makeGrpcRequest("172.17.0.2:50051")
}

func makeGrpcRequest(addr string) {
	client, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		fmt.Printf("error constructing grpc client: %s\n", err)
		os.Exit(1)
	}

	trayceClient := api.NewTrayceAgentClient(client)

	// reply, err := trayceClient.SendAgentStarted(context.Background(), &api.AgentStarted{Version: "1.2.3"})
	reply, err := trayceClient.SendContainersObserved(context.Background(), &api.Containers{
		Containers: []*api.Container{
			{
				Id:     "1234",
				Image:  "ubuntu",
				Ip:     "172.0.1.19",
				Name:   "HELLOWORLD!!!",
				Status: "running",
			},
		},
	})
	if err != nil {
		fmt.Printf("error sending agent started over grpc: %s\n", err)
		os.Exit(1)
	}

	fmt.Println("grpc reply:", reply.Status)
}
