package support

import (
	"context"

	"github.com/evanrolfe/dockerdog/api"
)

type GRPCHandler struct {
	api.UnimplementedDockerDogAgentServer
	callback             func(input *api.RequestObserved)
	agentStartedCallback func(input *api.AgentStarted)
}

func NewGRPCHandler() *GRPCHandler {
	return &GRPCHandler{
		callback:             func(input *api.RequestObserved) {},
		agentStartedCallback: func(input *api.AgentStarted) {},
	}
}

func (ts *GRPCHandler) SetCallback(callback func(input *api.RequestObserved)) {
	ts.callback = callback
}

func (ts *GRPCHandler) SetAgentStartedCallback(callback func(input *api.AgentStarted)) {
	ts.agentStartedCallback = callback
}

// SendRequestObserved implements helloworld.GreeterServer
func (ts *GRPCHandler) SendRequestObserved(ctx context.Context, input *api.RequestObserved) (*api.Reply, error) {
	// fmt.Printf(
	// 	"\nREQUEST RECEIVED:\nLocalAddr: %s\nRemoteAddr: %s\nRequest:\n%s\nResponse:\n%s\n",
	// 	input.LocalAddr,
	// 	input.RemoteAddr,
	// 	string(input.Request),
	// 	string(input.Response),
	// )

	ts.callback(input)
	return &api.Reply{Status: "success "}, nil
}

func (ts *GRPCHandler) SendAgentStarted(ctx context.Context, input *api.AgentStarted) (*api.Reply, error) {
	ts.agentStartedCallback(input)
	return &api.Reply{Status: "success "}, nil
}
