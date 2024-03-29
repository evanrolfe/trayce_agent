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

	"github.com/docker/docker/client"
)

type Containers struct {
	containerIds     []string
	dockerClient     *client.Client
	filterCmd        string
	libSSLVersionMap map[string]LibSSL
}

type Proc struct {
	Pid           uint32
	Ip            uint32
	ExecPath      string
	LibSSLVersion int
	LibSSLPath    string
}

type Container struct {
	Id            string
	Pid           uint32
	Ip            uint32
	RootFSPath    string
	LibSSLVersion int
	LibSSLPath    string
	NodePath      string
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
		containerIds:     []string{},
		dockerClient:     dockerC,
		filterCmd:        filterCmd,
		libSSLVersionMap: map[string]LibSSL{},
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

		libSSL := c.getLibSSL(containerId, containerFSPath)

		// Get the container's proccess ids
		pids, err := c.getPidsForContainer(containerId)
		if err != nil {
			fmt.Println("[ERROR] getPidsForContainer()", containerId, ", err:", err)
			continue
		}

		for _, pid := range pids {
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
				Pid:           uint32(pid),
				Ip:            ip,
				ExecPath:      execPathHost,
				LibSSLVersion: libSSL.Version,
				LibSSLPath:    libSSL.Path,
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

		nodePath := path.Join(containerFSPath, "/usr/bin/node")
		libSSL := c.getLibSSL(containerId, containerFSPath)

		containers[containerId] = Container{
			Id:            containerId,
			Pid:           uint32(container.State.Pid),
			Ip:            ip,
			RootFSPath:    containerFSPath,
			LibSSLVersion: libSSL.Version,
			LibSSLPath:    libSSL.Path,
			NodePath:      nodePath,
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
		return nil, fmt.Errorf("no index found for PID from docker.ContainerTop()")
	}

	// Extract the index of the Command in the results
	indexCmd := -1
	for i, title := range result.Titles {
		if title == "CMD" {
			indexCmd = i
		}
	}
	if indexCmd == -1 {
		return nil, fmt.Errorf("no index found for CMD from docker.ContainerTop()")
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

func (c *Containers) getLibSSL(containerId string, rootFSPath string) LibSSL {
	// First check if we have cached the version for this containerId
	version, exists := c.libSSLVersionMap[containerId]
	if exists {
		return version
	}

	libPaths := map[string]int{
		"/usr/lib/x86_64-linux-gnu/libssl.so.3":   3,
		"/usr/lib/x86_64-linux-gnu/libssl.so.1.1": 1,
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
