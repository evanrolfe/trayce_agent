package docker

import (
	"context"
	"fmt"
	"net"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/docker/docker/client"
)

type Containers struct {
	containerIds []string
	dockerClient *client.Client
	filterCmd    string
}

type Proc struct {
	Pid      uint32
	Ip       uint32
	ExecPath string
}

type Container struct {
	Pid        uint32
	Ip         uint32
	RootFSPath string
}

func NewContainers(filterCmd string) *Containers {
	dockerC, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		panic(err)
	}

	return &Containers{
		containerIds: []string{},
		dockerClient: dockerC,
		filterCmd:    filterCmd,
	}
}

func (c *Containers) GetProcsToIntercept() map[uint32]Proc {
	procs := map[uint32]Proc{}

	for _, containerId := range c.containerIds {
		// Get the container's IP address
		container, _ := c.dockerClient.ContainerInspect(context.Background(), containerId)
		if container.NetworkSettings == nil {
			continue
		}

		containerFSPath := fmt.Sprintf("/proc/%v/root", container.State.Pid)
		ip := ipStringToUint32(container.NetworkSettings.IPAddress)

		// Get the container's proccess ids
		for _, pid := range c.getPidsForContainer(containerId) {
			// On linux, given a proc id 123, the file at /proc/123/exe is a symlink to the actual binary being run
			// However its path is relative to the container its running on
			execPath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
			if err != nil {
				fmt.Println("Error os.Readlink()=", err)
				continue
			}

			// Prepend the path to the proc's container's filesystem so we get the path to the bin from the host container
			execPathHost := path.Join(containerFSPath, execPath)
			_, err = os.Stat(execPathHost)
			if err != nil {
				fmt.Println("Error: GetProcsToIntercept(), no file exists at", execPathHost)
				continue
			}

			procs[uint32(pid)] = Proc{
				Pid:      uint32(pid),
				Ip:       ip,
				ExecPath: execPathHost,
			}
		}
	}

	return procs
}

func (c *Containers) GetContainersToIntercept() map[string]Container {
	containers := map[string]Container{}

	for _, containerId := range c.containerIds {
		// Get the container's IP address
		container, _ := c.dockerClient.ContainerInspect(context.Background(), containerId)
		if container.NetworkSettings == nil {
			continue
		}

		containerFSPath := fmt.Sprintf("/proc/%v/root", container.State.Pid)
		ip := ipStringToUint32(container.NetworkSettings.IPAddress)

		containers[containerId] = Container{
			Pid:        uint32(container.State.Pid),
			Ip:         ip,
			RootFSPath: containerFSPath,
		}
	}

	return containers
}

func (c *Containers) GetIdFromPid(pid int) string {
	return ""
}

func (c *Containers) SetContainers(containerIds []string) {
	c.containerIds = containerIds
}

func (c *Containers) getPidsForContainer(containerId string) []int {
	result, err := c.dockerClient.ContainerTop(context.Background(), containerId, []string{})
	if err != nil {
		fmt.Println("[Containers] ContainerTop() error:", err)
	}

	// Extract the index of the PID in the results
	indexPid := -1
	for i, title := range result.Titles {
		if title == "PID" {
			indexPid = i
		}
	}
	if indexPid == -1 {
		panic("no index found for PID from docker.ContainerTop()")
	}

	// Extract the index of the Command in the results
	indexCmd := -1
	for i, title := range result.Titles {
		if title == "CMD" {
			indexCmd = i
		}
	}
	if indexCmd == -1 {
		panic("no index found for CMD from docker.ContainerTop()")
	}

	// Collect the PIDs
	pids := []int{}
	for i := 0; i < len(result.Processes); i++ {
		cmd := result.Processes[i][indexCmd]
		pidStr := result.Processes[i][indexPid]
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			panic(err)
		}

		if (c.filterCmd == "" || strings.Contains(cmd, c.filterCmd)) && !strings.Contains(cmd, "/app/dd_agent") {
			pids = append(pids, pid)
		}
	}

	return pids
}

func ipStringToUint32(ipStr string) uint32 {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		fmt.Println("[Error] unable to convert ip to uint32 net.ParseIP()")
		return 0
	}

	// Convert the IP address to a 4-byte slice (IPv4)
	ip = ip.To4()
	if ip == nil {
		fmt.Println("[Error] unable to convert ip to uint32 To4()")
		return 0
	}

	// Convert the 4-byte slice to a uint32
	ipUint32 := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])

	return ipUint32
}
