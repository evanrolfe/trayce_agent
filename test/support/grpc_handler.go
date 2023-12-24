package support

import (
	"context"
	"log"

	"github.com/evanrolfe/trayce_agent/api"
)

type GRPCHandler struct {
	api.UnimplementedTrayceAgentServer
	callback             func(input *api.Flows)
	agentStartedCallback func(input *api.AgentStarted)
	containerIds         []string
}

func NewGRPCHandler() *GRPCHandler {
	return &GRPCHandler{
		callback:             func(input *api.Flows) {},
		agentStartedCallback: func(input *api.AgentStarted) {},
	}
}

func (ts *GRPCHandler) SetContainerIds(containerIds []string) {
	ts.containerIds = containerIds
}

func (ts *GRPCHandler) SetCallback(callback func(input *api.Flows)) {
	ts.callback = callback
}

func (ts *GRPCHandler) SetAgentStartedCallback(callback func(input *api.AgentStarted)) {
	ts.agentStartedCallback = callback
}

func (ts *GRPCHandler) SendFlowsObserved(ctx context.Context, input *api.Flows) (*api.Reply, error) {
	ts.callback(input)
	return &api.Reply{Status: "success "}, nil
}

func (ts *GRPCHandler) SendAgentStarted(ctx context.Context, input *api.AgentStarted) (*api.Reply, error) {
	ts.agentStartedCallback(input)
	return &api.Reply{Status: "success "}, nil
}

func (ts *GRPCHandler) OpenCommandStream(srv api.TrayceAgent_OpenCommandStreamServer) error {
	log.Println("start new stream")

	command := api.Command{
		Type:     "set_settings",
		Settings: &api.Settings{ContainerIds: ts.containerIds},
	}

	if err := srv.Send(&command); err != nil {
		log.Printf("send error %v", err)
	}
	log.Printf("sent new command:", command.Type)

	return nil
}
