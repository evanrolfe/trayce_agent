package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/evanrolfe/dockerdog/api"
	"github.com/evanrolfe/dockerdog/internal"
	"github.com/evanrolfe/dockerdog/internal/sockets"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	bpfFilePath       = "bundle/ssl.bpf.o"
	btfFilePath       = "bundle/6.2.0-26-generic.btf"
	sslLibDefault     = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	grpcServerDefault = "localhost:50051"
)

func extractFile(data []byte, destPath string) {
	f, err := os.Create(destPath)
	if err != nil {
		panic(err)
	}

	_, err = f.Write(data)
	if err != nil {
		panic(err)
	}

	f.Close()
}

func main() {
	// Parse Command line args
	var pid int
	var libSslPath, grpcServerAddr string
	flag.IntVar(&pid, "pid", 0, "The PID of the docker container to instrument. Or 0 to intsrument this container.")
	flag.StringVar(&libSslPath, "libssl", sslLibDefault, "The path to the libssl shared object.")
	flag.StringVar(&grpcServerAddr, "grpcaddr", grpcServerDefault, "The address of the GRPC server to send observations to.")
	flag.Parse()

	fmt.Println("PID: ", pid)
	fmt.Println("libssl: ", libSslPath)

	// Extract bundled files
	bpfBytes := internal.MustAsset(bpfFilePath)
	btfBytes := internal.MustAsset(btfFilePath)
	btfDestFile := "./5.8.0-23-generic.btf"
	extractFile(btfBytes, btfDestFile)
	defer os.Remove(btfDestFile)

	// Start the agent
	agent := internal.NewBPFAgent(bpfBytes, btfFilePath, libSslPath)
	defer agent.Close()

	// Create a channel to receive interrupt signals
	interrupt := make(chan os.Signal, 1)
	socketFlowChan := make(chan sockets.Flow)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	fmt.Println("Agent listing...")
	go agent.ListenForEvents(socketFlowChan)

	// Start a goroutine to handle the interrupt signal
	var wg sync.WaitGroup
	wg.Add(1)

	// API Client
	// Set up a connection to the server.
	conn, err := grpc.Dial(grpcServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Println("[ERROR] could not connect to GRPC server: %v", err)
		return
	}
	defer conn.Close()

	grpcClient := api.NewDockerDogAgentClient(conn)

	go func() {
		for {
			// Check if the interrupt signal has been received
			select {
			case <-interrupt:
				wg.Done()
				return
			case flow := <-socketFlowChan:
				fmt.Printf("[Flow] %s - Local: %s, Remote: %s\n", "", flow.LocalAddr, flow.RemoteAddr)
				flow.Debug()

				// Contact the server and print out its response.
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()

				apiReq := &api.FlowObserved{
					LocalAddr:  flow.LocalAddr,
					RemoteAddr: flow.RemoteAddr,
					L4Protocol: flow.L4Protocol,
					L7Protocol: flow.L7Protocol,
					Request:    flow.Request,
					Response:   flow.Response,
				}

				_, err := grpcClient.SendFlowObserved(ctx, apiReq)
				if err != nil {
					fmt.Println("[ERROR] could not request: %v", err)
				}
			}
		}
	}()

	_, err = grpcClient.SendAgentStarted(context.Background(), &api.AgentStarted{})
	if err != nil {
		fmt.Println("[ERROR] could not request: %v", err)
	}

	wg.Wait()

	fmt.Printf("Done, closing agent. PID: %d. GID: %d. EGID: %d \n", os.Getpid(), os.Getgid(), os.Getegid())

	// agent.Close()
}
