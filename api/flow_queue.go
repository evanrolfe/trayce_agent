package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/evanrolfe/trayce_agent/internal/sockets"
)

type FlowQueue struct {
	grpcClient TrayceAgentClient
	flows      []*Flow
	batchSize  int
	v          bool
	licenseKey string
}

func NewFlowQueue(grpcClient TrayceAgentClient, batchSize int) *FlowQueue {
	return &FlowQueue{
		grpcClient: grpcClient,
		batchSize:  batchSize,
	}
}

func (fq *FlowQueue) Start(ctx context.Context, inputChan chan sockets.Flow) {
	// Listen to the input channel and queue any flows received from it
	go func(ctx context.Context) {
		for {
			select {
			case <-ctx.Done():
				fmt.Println("[FlowQueue] stopping receiver go-routine")
				return
			case flow := <-inputChan:
				fmt.Println("[FlowQueue] received flow", flow.UUID)
				flow = fq.formatFlow(flow)
				blackOnYellow := "\033[30;43m"
				reset := "\033[0m"

				apiFlow := convertToAPIFlow(flow)

				fmt.Printf("%s[Flow]%s Source: %s, Dest: %s, UUID: %s\n", blackOnYellow, reset, flow.SourceAddr, flow.DestAddr, flow.UUID)
				flow.Debug()

				// Queue the Flow
				fq.flows = append(fq.flows, apiFlow)

				if len(fq.flows)%10 == 0 {
					fmt.Println("[FlowQueue] received", len(fq.flows), "flows")
				}
			}
		}
	}(ctx)

	go func(ctx context.Context) {
		for {
			select {
			case <-time.After(100 * time.Millisecond): // Wait for 100ms
				fq.processQueue()
			case <-ctx.Done(): // Check if the context has been cancelled
				fmt.Println("[FlowQueue] stopping processQueue go-routine")
				return // Exit the loop (and possibly the goroutine)
			}
		}
	}(ctx)

	fmt.Println("[FlowQueue] running...")
}

func (fq *FlowQueue) SetLicenseKey(licenseKey string) {
	fq.licenseKey = licenseKey
	fq.verifyLicenseKey()
}

// TODO: Sometimes this doesn't process the flows in order, possibly because the FlowQueue is instantiated
// inside another go routine so there are other flow queues running?
func (fq *FlowQueue) processQueue() {
	if len(fq.flows) == 0 {
		return
	}

	flows := fq.shiftQueue(fq.batchSize)

	apiFlows := &Flows{Flows: flows}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	fmt.Println("[FlowQueue] sending flows", len(apiFlows.Flows))
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

func (fq *FlowQueue) verifyLicenseKey() {
	if fq.licenseKey == "" {
		fq.v = false
		return
	}

	url := fmt.Sprintf("https://get.trayce.dev/verify/%s", fq.licenseKey)
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("ERROR: failed to verify license: %w", err)
		fq.v = false
		return
	}
	defer resp.Body.Close()

	type LicenseResponse struct {
		Status string `json:"status"`
	}

	var license LicenseResponse
	if err := json.NewDecoder(resp.Body).Decode(&license); err != nil {
		fmt.Println("ERROR: failed to decode license response: %w", err)
		fq.v = false
		return
	}

	if license.Status == "active" {
		fmt.Println("License verified")
		fq.v = true
	} else {
		fmt.Println("License is inactive")
		fq.v = false
	}
}
