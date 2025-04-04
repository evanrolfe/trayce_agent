package api_test

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/evanrolfe/trayce_agent/api"
	"github.com/evanrolfe/trayce_agent/internal/sockets"
	"github.com/evanrolfe/trayce_agent/test/support"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	grpcPort  = 50051
	numFlows  = 100
	batchSize = 50
)

var _ = Describe("FlowQueue", func() {
	Context("Receiving a Connect, Data (request) events", Ordered, func() {
		var grpcHandler *support.GRPCHandler
		var conn *grpc.ClientConn
		var flowQueue *api.FlowQueue
		inputChan := make(chan sockets.Flow)
		flowsReceived := []*api.Flow{}

		BeforeAll(func() {
			// Start GRPC server
			lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", grpcPort))
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

			// Connect to GRPC server
			conn, err = grpc.Dial(fmt.Sprintf("localhost:%d", grpcPort), grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				fmt.Println("[ERROR] could not connect to GRPC server:", err)
				return
			}
			grpcClient := api.NewTrayceAgentClient(conn)

			// FlowQueue
			flowQueue = api.NewFlowQueue(grpcClient, batchSize)
			go flowQueue.Start(context.Background(), inputChan)

			// Create a context with a timeout
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			// Get the flows set to us via GRPC
			grpcHandler.SetCallback(func(input *api.Flows) {
				// fmt.Println("[Test] received flows:")
				// for _, flow := range input.Flows {
				// 	fmt.Println("	", string(flow.Request))
				// }

				flowsReceived = append(flowsReceived, input.Flows...)

				if len(flowsReceived) == numFlows {
					cancel()
				}
			})

			// Send some flows to the FlowQueue
			for i := 0; i < numFlows; i++ {
				flow1 := sockets.NewFlowRequest(
					"1999742d-d2b0-4f3a-a8d7-ae7a546e95c1",
					"127.0.0.1",
					"192.168.0.1",
					"tcp",
					"http",
					1,
					2,
					&sockets.HTTPRequest{
						Method:      "GET",
						Path:        "/",
						Host:        "",
						HttpVersion: "1.1",
					},
				)
				inputChan <- *flow1
			}

			// Wait for the context to complete
			<-ctx.Done()
		})

		AfterAll(func() {
			conn.Close()
		})

		It("returns a flow", func() {
			Expect(len(flowsReceived)).To(Equal(100))
		})
	})
})
