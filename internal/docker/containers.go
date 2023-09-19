package docker

import (
	"fmt"

	"github.com/evanrolfe/dockerdog/api"
)

type Containers struct {
}

func NewContainers() *Containers {
	return &Containers{}
}

func (c *Containers) GetPidsToIntercept() {

}

func (c *Containers) GetIdFromPid(pid int) string {
	return ""
}

func (c *Containers) SetSettings(settings *api.Settings) {
	fmt.Println("-----> Listener: only intercepting containers:", settings.ContainerIds)

	// TODO
}
