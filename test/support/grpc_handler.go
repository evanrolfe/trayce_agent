package support

import (
	"context"

	"github.com/evanrolfe/dockerdog/api"
)

type GRPCHandler struct {
	api.UnimplementedDockerDogAgentServer
	callback             func(input *api.FlowObserved)
	agentStartedCallback func(input *api.AgentStarted)
}

func NewGRPCHandler() *GRPCHandler {
	return &GRPCHandler{
		callback:             func(input *api.FlowObserved) {},
		agentStartedCallback: func(input *api.AgentStarted) {},
	}
}

func (ts *GRPCHandler) SetCallback(callback func(input *api.FlowObserved)) {
	ts.callback = callback
}

func (ts *GRPCHandler) SetAgentStartedCallback(callback func(input *api.AgentStarted)) {
	ts.agentStartedCallback = callback
}

func (ts *GRPCHandler) SendFlowObserved(ctx context.Context, input *api.FlowObserved) (*api.Reply, error) {
	ts.callback(input)
	return &api.Reply{Status: "success "}, nil
}

func (ts *GRPCHandler) SendAgentStarted(ctx context.Context, input *api.AgentStarted) (*api.Reply, error) {
	ts.agentStartedCallback(input)
	return &api.Reply{Status: "success "}, nil
}
