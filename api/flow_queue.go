package api

import (
	"context"
	"fmt"
	"time"

	"github.com/evanrolfe/dockerdog/internal/sockets"
)

type FlowQueue struct {
	grpcClient DockerDogAgentClient
	flows      []*Flow
	batchSize  int
}

func NewFlowQueue(grpcClient DockerDogAgentClient, batchSize int) *FlowQueue {
	return &FlowQueue{
		grpcClient: grpcClient,
		batchSize:  batchSize,
	}
}

func (fq *FlowQueue) Start(inputChan chan sockets.Flow) {
	// Listen to the input channel and queue any flows received from it
	go func() {
		for {
			flow := <-inputChan

			// Convert socket.Flow to Flow
			apiFlow := &Flow{
				LocalAddr:  flow.LocalAddr,
				RemoteAddr: flow.RemoteAddr,
				L4Protocol: flow.L4Protocol,
				L7Protocol: flow.L7Protocol,
				Request:    flow.Request,
				Response:   flow.Response,
			}
			// Queue the Flow
			fq.flows = append(fq.flows, apiFlow)

			if len(fq.flows)%10 == 0 {
				fmt.Println("[FlowQueue] received", len(fq.flows), "flows")
			}
		}
	}()

	for {
		time.Sleep(100 * time.Millisecond)
		fq.processQueue()
	}
}

func (fq *FlowQueue) processQueue() {
	if len(fq.flows) == 0 {
		return
	}

	flows := fq.shiftQueue(fq.batchSize)

	apiFlows := &Flows{Flows: flows}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := fq.grpcClient.SendFlowsObserved(ctx, apiFlows)
	if err != nil {
		fmt.Println("[ERROR] could not request:", err)
	}
}

func (fq *FlowQueue) shiftQueue(n int) []*Flow {
	if len(fq.flows) < n {
		n = len(fq.flows)
	}
	flows := fq.flows[0:n]

	fq.flows = fq.flows[n:]

	return flows
}

func (fq *FlowQueue) clearQueue() {
	fq.flows = []*Flow{}
}

// func test() {
// 	for keepGoing := true; keepGoing; {
// 		var batch []string
// 		expire := time.After(maxTimeout)
// 		for {
// 			select {
// 			case value, ok := <-values:
// 				if !ok {
// 					keepGoing = false
// 					goto done
// 				}

// 				batch = append(batch, value)
// 				if len(batch) == maxItems {
// 					goto done
// 				}

// 			case <-expire:
// 				goto done
// 			}
// 		}

// 	}
// }
