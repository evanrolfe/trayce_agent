package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/evanrolfe/dockerdog/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	port           = 50051
	grpcServerAddr = "localhost:50051"
)

func main() {
	// Set up a connection to the server.
	conn, err := grpc.Dial(grpcServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Println("[ERROR] could not connect to GRPC server:", err)
		return
	}
	defer conn.Close()

	grpcClient := api.NewDockerDogAgentClient(conn)

	// Open command stream via GRPC
	stream, err := grpcClient.OpenCommandStream(context.Background())
	if err != nil {
		fmt.Println("[ERROR] openn stream error:", err)
	}

	// Create a channel to receive interrupt signals
	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, os.Interrupt, syscall.SIGTERM, syscall.SIGABRT)

	// Start a goroutine to handle the interrupt signal
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		for {
			<-interruptChan
			fmt.Print("Interrupt received")
			// Tell the Server to close this Stream, used to clean up running on the server
			err := stream.CloseSend()
			if err != nil {
				log.Fatal("Failed to close stream: ", err.Error())
			}
			wg.Done()
			fmt.Print("Done")
			return
		}
	}()

	go func() {
		for {
			// Recieve on the stream
			resp, err := stream.Recv()
			if err == io.EOF {
				return
			}
			if err != nil {
				panic(err)
			}
			if resp.Type == "hello_world" {
				fmt.Println(resp.Settings.ContainerIds)
			}
		}
	}()

	wg.Wait()

	fmt.Println("All done")
}
