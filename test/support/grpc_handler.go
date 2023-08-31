package support

import (
	"context"

	"github.com/evanrolfe/dockerdog/api"
)

type GRPCHandler struct {
	api.UnimplementedDockerDogAgentServer
	callback func(input *api.RequestObserved)
}

func NewGRPCHandler() *GRPCHandler {
	return &GRPCHandler{
		callback: func(input *api.RequestObserved) {},
	}
}

func (ts *GRPCHandler) SetCallback(callback func(input *api.RequestObserved)) {
	ts.callback = callback
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
