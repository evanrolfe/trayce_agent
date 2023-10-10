package support

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/evanrolfe/dockerdog/api"
)

type GRPCHandler struct {
	api.UnimplementedDockerDogAgentServer
	callback             func(input *api.Flows)
	agentStartedCallback func(input *api.AgentStarted)
}

func NewGRPCHandler() *GRPCHandler {
	return &GRPCHandler{
		callback:             func(input *api.Flows) {},
		agentStartedCallback: func(input *api.AgentStarted) {},
	}
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

func (ts *GRPCHandler) OpenCommandStream(srv api.DockerDogAgent_OpenCommandStreamServer) error {
	log.Println("start new stream")
	hostname, err := os.Hostname()
	if err != nil {
		panic(err)
	}

	for i := 0; i < 3; i++ {
		command := api.Command{
			Type:     "set_settings",
			Settings: &api.Settings{ContainerIds: []string{hostname}},
		}

		if err := srv.Send(&command); err != nil {
			log.Printf("send error %v", err)
		}
		log.Printf("sent new command:", command.Type)
		time.Sleep(time.Second)
	}

	return nil
}
