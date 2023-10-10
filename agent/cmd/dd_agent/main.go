package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/evanrolfe/dockerdog/api"
	"github.com/evanrolfe/dockerdog/internal"
	"github.com/evanrolfe/dockerdog/internal/sockets"
	"github.com/evanrolfe/dockerdog/internal/utils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	bpfFilePath       = "bundle/ssl.bpf.o"
	btfFilePath       = "bundle/6.2.0-26-generic.btf"
	sslLibDefault     = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	grpcServerDefault = "localhost:50051"
)

type Settings struct {
	ContainerIds []string
}

func main() {
	// Parse Command line args
	var pid int
	var libSslPath, grpcServerAddr, filterCmd string
	flag.IntVar(&pid, "pid", 0, "The PID of the docker container to instrument. Or 0 to intsrument this container.")
	flag.StringVar(&libSslPath, "libssl", sslLibDefault, "The path to the libssl shared object.")
	flag.StringVar(&grpcServerAddr, "grpcaddr", grpcServerDefault, "The address of the GRPC server to send observations to.")
	flag.StringVar(&filterCmd, "filtercmd", "", "Only observe traffic from processes who's command contains this string")
	flag.Parse()

	fmt.Println("PID: ", pid)
	fmt.Println("libssl: ", libSslPath)

	// Extract bundled files
	bpfBytes := internal.MustAsset(bpfFilePath)
	btfBytes := internal.MustAsset(btfFilePath)
	btfDestFile := "./5.8.0-23-generic.btf"
	utils.ExtractFile(btfBytes, btfDestFile)
	defer os.Remove(btfDestFile)

	// Create a channel to receive interrupt signals
	interruptChan := make(chan os.Signal, 1)
	interruptChan2 := make(chan os.Signal, 2)
	socketFlowChan := make(chan sockets.Flow)
	signal.Notify(interruptChan, os.Interrupt, syscall.SIGTERM, syscall.SIGABRT)
	signal.Notify(interruptChan2, os.Interrupt, syscall.SIGTERM, syscall.SIGABRT)

	// Start the listener
	listener := internal.NewListener(bpfBytes, btfFilePath, libSslPath, filterCmd)
	defer listener.Close()

	fmt.Println("Agent listing...")
	go listener.Start(socketFlowChan)

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
	defer func() { fmt.Println("closing grpc conn"); conn.Close() }()

	grpcClient := api.NewDockerDogAgentClient(conn)

	// Open command stream via GRPC
	stream, err := grpcClient.OpenCommandStream(context.Background())
	if err != nil {
		fmt.Println("[ERROR] openn stream error %v", err)
	}

	go func() {
		for {
			<-interruptChan
			fmt.Println("Interrupt received")
			// Tell the Server to close this Stream, used to clean up running on the server
			err := stream.CloseSend()
			if err != nil {
				log.Fatal("Failed to close stream: ", err.Error())
			}
			wg.Done()
			return
		}
	}()

	flowQueue := api.NewFlowQueue(grpcClient, 100)
	go flowQueue.Start(socketFlowChan)

	// go func() {
	// 	for {
	// 		// Check if the interrupt signal has been received
	// 		select {
	// 		case flow := <-socketFlowChan:
	// 			// Contact the server and print out its response.
	// 			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	// 			defer cancel()

	// 			apiFlow := &api.Flow{
	// 				LocalAddr:  flow.LocalAddr,
	// 				RemoteAddr: flow.RemoteAddr,
	// 				L4Protocol: flow.L4Protocol,
	// 				L7Protocol: flow.L7Protocol,
	// 				Request:    flow.Request,
	// 				Response:   flow.Response,
	// 			}
	// 			apiFlows := &api.Flows{Flows: []*api.Flow{apiFlow}}

	// 			_, err := grpcClient.SendFlowsObserved(ctx, apiFlows)
	// 			if err != nil {
	// 				fmt.Println("[ERROR] could not request: %v", err)
	// 			}
	// 		}
	// 	}
	// }()

	// IMPORTANT: This seems to block the entire thing if it doesn't receive the set_settings message from the server!!!
	// TODO: Figure this out
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
			if resp.Type == "set_settings" {
				fmt.Println(resp.Settings.ContainerIds)
				listener.SetContainers(resp.Settings.ContainerIds)
			}
		}
	}()

	_, err = grpcClient.SendAgentStarted(context.Background(), &api.AgentStarted{})
	if err != nil {
		fmt.Println("[ERROR] could not request: %v", err)
	}

	wg.Wait()

	fmt.Printf("Done, closing agent. PID: %d. GID: %d. EGID: %d \n", os.Getpid(), os.Getgid(), os.Getegid())
}
