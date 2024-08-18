package docker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

// Containers is a wrapper around the docker client and provides helper methods for fetching containers & procs running
// in docker.
type Containers struct {
	containerIDs     []string
	dockerClient     *client.Client
	filterCmd        string
	libSSLVersionMap map[string]LibSSL
}

type Proc struct {
	PID           uint32
	IP            uint32
	ContainerId   string
	ExecPath      string
	LibSSLVersion int
	LibSSLPath    string
}

type Container struct {
	ID            string
	PID           uint32
	IP            uint32
	RootFSPath    string
	LibSSLVersion int
	LibSSLPath    string
	NodePath      string
}

// ContainerGUI contains the container information which is needed to display in the GUI containers dialog, it gets
// sent to the GUI over GRPC.
type ContainerGUI struct {
	ID     string
	Image  string
	IP     string
	Name   string
	Status string
}

type LibSSL struct {
	Version int
	Path    string
}

func NewContainers(filterCmd string) *Containers {
	dockerC, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		panic(err)
	}

	return &Containers{
		containerIDs:     []string{},
		dockerClient:     dockerC,
		filterCmd:        filterCmd,
		libSSLVersionMap: map[string]LibSSL{},
	}
}

func (c *Containers) GetProcsToIntercept() map[uint32]Proc {
	procs := map[uint32]Proc{}

	for _, containerId := range c.containerIDs {
		// Get the container's IP address
		container, _ := c.dockerClient.ContainerInspect(context.Background(), containerId)
		if container.NetworkSettings == nil {
			continue
		}

		ip := ipStringToUint32(extractIP(container))

		containerFSPath := fmt.Sprintf("/proc/%v/root", container.State.Pid)
		libSSL := c.getLibSSL(containerId, containerFSPath)

		// Get the container's proccess ids
		pids, err := c.getPidsForContainer(containerId)
		if err != nil {
			fmt.Println("[ERROR] getPidsForContainer()", containerId, ", err:", err)
			// If this fails then we assume that its because the container has been stopped so we remove it, it would be
			// nice if docker gave us proper errors so we could differentiate between container stopped and other errors
			c.removeContainer(containerId)
			continue
		}

		for _, pid := range pids {
			// On linux, given a proc id 123, the file at /proc/123/exe is a symlink to the actual binary being run
			// However its path is relative to the container its running on
			execPath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
			if err != nil {
				// This will happen for short-lived requests
				procs[uint32(pid)] = Proc{
					PID:           uint32(pid),
					IP:            ip,
					ExecPath:      "",
					LibSSLVersion: libSSL.Version,
					LibSSLPath:    libSSL.Path,
					ContainerId:   containerId,
				}
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
				PID:           uint32(pid),
				IP:            ip,
				ExecPath:      execPathHost,
				LibSSLVersion: libSSL.Version,
				LibSSLPath:    libSSL.Path,
				ContainerId:   containerId,
			}
		}
	}

	return procs
}

func (c *Containers) GetContainersToIntercept() map[string]Container {
	containers := map[string]Container{}

	for _, containerId := range c.containerIDs {
		// Get the container's IP address
		container, _ := c.dockerClient.ContainerInspect(context.Background(), containerId)
		if container.NetworkSettings == nil {
			continue
		}

		ip := ipStringToUint32(extractIP(container))

		containerFSPath := fmt.Sprintf("/proc/%v/root", container.State.Pid)
		nodePath := path.Join(containerFSPath, "/usr/bin/node")
		libSSL := c.getLibSSL(containerId, containerFSPath)

		containers[containerId] = Container{
			ID:            containerId,
			PID:           uint32(container.State.Pid),
			IP:            ip,
			RootFSPath:    containerFSPath,
			LibSSLVersion: libSSL.Version,
			LibSSLPath:    libSSL.Path,
			NodePath:      nodePath,
		}
	}

	return containers
}

func (c *Containers) SetContainers(containerIDs []string) {
	c.containerIDs = containerIDs
}

// GetAllContainers returns all containers running on the machine
func (c *Containers) GetAllContainers() ([]ContainerGUI, error) {
	containersOutput := []ContainerGUI{}

	containers, err := c.dockerClient.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		return containersOutput, err
	}

	for _, container := range containers {
		containerJSON, err := c.dockerClient.ContainerInspect(context.Background(), container.ID)
		if err != nil {
			fmt.Println("[ERROR] ContainerInspect():", err)
			continue
		}
		if containerJSON.NetworkSettings == nil || containerJSON.State == nil {
			fmt.Println("[ERROR] GetAllContainers() no NetworkSettings present on", containerJSON.ID)
			continue
		}
		if containerJSON.Config == nil {
			fmt.Println("[ERROR] GetAllContainers() no config present on", containerJSON.ID)
			continue
		}

		containerGUI := ContainerGUI{
			ID:     containerJSON.ID[0:12],
			Image:  containerJSON.Config.Image,
			IP:     extractIP(containerJSON),
			Name:   containerJSON.Name,
			Status: containerJSON.State.Status,
		}
		containersOutput = append(containersOutput, containerGUI)
	}

	return containersOutput, nil
}

func (c *Containers) getPidsForContainer(containerId string) ([]int, error) {
	result, err := c.dockerClient.ContainerTop(context.Background(), containerId, []string{})
	if err != nil {
		return nil, err
	}

	// Extract the index of the PID in the results
	indexPid := -1
	for i, title := range result.Titles {
		if title == "PID" {
			indexPid = i
		}
	}
	if indexPid == -1 {
		return nil, fmt.Errorf("no index found for PID from docker.ContainerTop(), titles: %v", result.Titles)
	}

	// Extract the index of the Command in the results
	indexCmd := -1
	for i, title := range result.Titles {
		// It appears that some docker installations have this as CMD while others have COMMAND
		if title == "CMD" || title == "COMMAND" {
			indexCmd = i
		}
	}
	if indexCmd == -1 {
		return nil, fmt.Errorf("no index found for CMD from docker.ContainerTop(), titles: %v", result.Titles)
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

		if (c.filterCmd == "" || strings.Contains(cmd, c.filterCmd)) && !strings.Contains(cmd, "/app/trayce_agent") {
			pids = append(pids, pid)
		}
	}

	return pids, nil
}

func ipStringToUint32(ipStr string) uint32 {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		fmt.Println("[Error] unable to convert ip to uint32 net.ParseIP()", ipStr)
		return 0
	}

	// Convert the IP address to a 4-byte slice (IPv4)
	ip = ip.To4()
	if ip == nil {
		fmt.Println("[Error] unable to convert ip to uint32 To4()", ipStr)
		return 0
	}

	// Convert the 4-byte slice to a uint32
	ipUint32 := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])

	return ipUint32
}

func (c *Containers) getLibSSL(containerId string, rootFSPath string) LibSSL {
	// First check if we have cached the version for this containerId
	version, exists := c.libSSLVersionMap[containerId]
	if exists {
		return version
	}

	libPaths := map[string]int{
		"/usr/lib/x86_64-linux-gnu/libssl.so.3":    3,
		"/usr/lib/aarch64-linux-gnu/libssl.so.3":   3,
		"/usr/lib/x86_64-linux-gnu/libssl.so.1.1":  1,
		"/usr/lib/aarch64-linux-gnu/libssl.so.1.1": 1,
	}

	foundVersion := 0
	foundPath := ""
	for libPath, version := range libPaths {
		fullPath := path.Join(rootFSPath, libPath)
		if checkFileExists(fullPath) {
			foundVersion = version
			foundPath = fullPath
		}
	}

	libSSL := LibSSL{Version: foundVersion, Path: foundPath}
	c.libSSLVersionMap[containerId] = libSSL
	return libSSL
}

func checkFileExists(filePath string) bool {
	_, error := os.Stat(filePath)
	return !errors.Is(error, os.ErrNotExist)
}

func (c *Containers) removeContainer(containerId string) {
	newcontainerIDs := c.containerIDs[:0] // Create a new slice with zero length but same capacity as the original
	for _, value := range c.containerIDs {
		if value != containerId {
			newcontainerIDs = append(newcontainerIDs, value)
		}
	}

	c.containerIDs = newcontainerIDs
}

func extractIP(container types.ContainerJSON) string {
	if container.NetworkSettings.IPAddress != "" {
		return container.NetworkSettings.IPAddress
	}

	if len(container.NetworkSettings.Networks) > 0 {
		// If there are multiple networks, just pick the first one
		for _, network := range container.NetworkSettings.Networks {
			// NOTE this will be an empty string if the container is on the host network
			if network.IPAddress != "" {
				return network.IPAddress
			}
		}
	}

	return "0.0.0.0"
}
