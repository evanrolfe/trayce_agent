package internal

import (
	"context"
	"fmt"
	"time"

	"github.com/evanrolfe/dockerdog/api"
	"github.com/evanrolfe/dockerdog/internal/sockets"
)

type FlowQueue struct {
	grpcClient api.DockerDogAgentClient
	flows      []*api.Flow
}

func NewFlowQueue(grpcClient api.DockerDogAgentClient) *FlowQueue {
	return &FlowQueue{grpcClient: grpcClient}
}

func (fq *FlowQueue) Start(inputChan chan sockets.Flow) {
	go fq.startWorker()

	// Listen to the input channel and queue any flows received from it
	for {
		flow := <-inputChan

		// Convert socket.Flow to api.Flow
		apiFlow := &api.Flow{
			LocalAddr:  flow.LocalAddr,
			RemoteAddr: flow.RemoteAddr,
			L4Protocol: flow.L4Protocol,
			L7Protocol: flow.L7Protocol,
			Request:    flow.Request,
			Response:   flow.Response,
		}
		// Queue the Flow
		fq.flows = append(fq.flows, apiFlow)

		fq.sendFlows()
	}
}

func (fq *FlowQueue) sendFlows() {
	apiFlows := &api.Flows{Flows: fq.flows}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := fq.grpcClient.SendFlowsObserved(ctx, apiFlows)
	if err != nil {
		fmt.Println("[ERROR] could not request: %v", err)
	}

	fq.clearQueue()
}

func (fq *FlowQueue) clearQueue() {
	fq.flows = []*api.Flow{}
}

func (fq *FlowQueue) startWorker() {

}
