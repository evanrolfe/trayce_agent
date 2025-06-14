package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/evanrolfe/trayce_agent/api"
	"github.com/evanrolfe/trayce_agent/internal"
	"github.com/evanrolfe/trayce_agent/internal/config"
	"github.com/evanrolfe/trayce_agent/internal/docker"
	"github.com/evanrolfe/trayce_agent/internal/sockets"
	"github.com/evanrolfe/trayce_agent/internal/utils"
	"github.com/zcalusic/sysinfo"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

const (
	bpfFilePath       = "bundle/main.bpf.o"
	btfFilePath5      = "bundle/5.8.0-23-generic.btf"
	btfFilePath6      = "bundle/6.2.0-26-generic.btf"
	sslLibDefault     = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	grpcServerDefault = "localhost:50051"
	version           = "1.0.5"
)

type Settings struct {
	ContainerIds []string
}

type Error string

const (
	ErrServerUnavailable Error = "server unavailable"
	ErrStreamClosed      Error = "stream closed"
)

func (e Error) Error() string {
	return string(e)
}

func main() {
	// Parse Command line args
	var pid int
	var libSslPath, grpcServerAddr, filterCmd string
	var verbose bool
	flag.IntVar(&pid, "pid", 0, "The PID of the docker container to instrument. Or 0 to intsrument this container.")
	flag.StringVar(&libSslPath, "libssl", sslLibDefault, "The path to the libssl shared object.")
	flag.StringVar(&grpcServerAddr, "s", grpcServerDefault, "The address of the GRPC server to send observations to.")
	flag.StringVar(&filterCmd, "filtercmd", "", "Only observe traffic from processes who's command contains this string")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	flag.BoolVar(&verbose, "vv", false, "Enable verbose logging (shorthand)")
	versionFlg := flag.Bool("v", false, "print current TrayceAgent version")
	version2Flg := flag.Bool("version", false, "print current TrayceAgent version")
	flag.Parse()

	// Handle version flag:
	if *versionFlg || *version2Flg {
		fmt.Printf("TrayceAgent v%s\n", version)
		return
	}

	kernelVersion := getKernelVersionMajor()

	var btfFilePath string
	if kernelVersion == 6 {
		btfFilePath = btfFilePath6
	} else if kernelVersion == 5 {
		btfFilePath = btfFilePath5
	} else {
		fmt.Println("Linux kernel version", kernelVersion, "is not supported, please upgrade to >= 5.0.0")
	}

	// Ensure the tracepoints are mounted (i.e. sched_process_fork)
	if !isMounted("/sys/kernel/debug/tracing") {
		err := syscall.Mount("debugfs", "/sys/kernel/debug", "debugfs", 0, "")
		if err != nil {
			fmt.Println("Failing to mount debugfs:", err)
			return
		}
	}

	// Extract bundled files
	bpfBytes := internal.MustAsset(bpfFilePath)
	btfBytes := internal.MustAsset(btfFilePath)
	btfDestFile := "./5.8.0-23-generic.btf"
	utils.ExtractFile(btfBytes, btfDestFile)
	defer os.Remove(btfDestFile)

	// Create a channel to receive interrupt signals
	interruptChan := make(chan os.Signal, 1)
	socketFlowChan := make(chan sockets.Flow, 1000)
	signal.Notify(interruptChan, os.Interrupt, syscall.SIGTERM, syscall.SIGABRT)

	// Create config
	cfg := config.NewConfig(btfFilePath, libSslPath, filterCmd, verbose)

	// Start the listener
	listener := internal.NewListener(cfg, bpfBytes)
	defer listener.Close()

	go listener.Start(socketFlowChan)
	fmt.Println("Agent listening...")

	// Try to connect to GRPC server, if the server is unavailable them keep retrying every second
	go func() {
		for {
			// Connect to the GRPC server
			fmt.Println("[GRPC] connecting to server at", grpcServerAddr)
			conn, err := grpc.Dial(
				grpcServerAddr,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithKeepaliveParams(keepalive.ClientParameters{
					Time:                3 * time.Second, // send pings every 10 seconds if there is no activity
					Timeout:             time.Second,     // wait a second for ping ack before considering the connection dead
					PermitWithoutStream: true,            // send pings even without active streams
				}),
			)
			if err != nil {
				return
			}
			defer func() { fmt.Println("closing grpc conn"); conn.Close() }()

			grpcClient := api.NewTrayceAgentClient(conn)

			// Send flows from the socket flow channel to the GRPC client via FlowQueue (for batching + rate limiting)
			ctx, cancel := context.WithCancel(context.Background())
			flowQueue := api.NewFlowQueue(grpcClient, 1000)
			flowQueue.Start(ctx, socketFlowChan)

			// Start the main event loop which recieves commands from the GRPC CommandStream
			// openCommandStreamAndAwait blocks until an error occurs
			err = openCommandStreamAndAwait(grpcClient, listener, flowQueue)
			if errors.Is(err, ErrStreamClosed) {
				fmt.Println("[GRPC] StreamClosed:", err)
				cancel()
			} else if errors.Is(err, ErrServerUnavailable) {
				fmt.Println("[GRPC] ServerUnavailable:", err)
				cancel()
				time.Sleep(time.Second)
				continue
			} else if err != nil {
				fmt.Println("[ERROR]", err)
				cancel()
			}
		}
	}()

	// Wait until the interrupt signal is received
	<-interruptChan

	fmt.Printf("Done, closing agent. PID: %d. GID: %d. EGID: %d \n", os.Getpid(), os.Getgid(), os.Getegid())
}

func openCommandStreamAndAwait(grpcClient api.TrayceAgentClient, listener *internal.Listener, flowQueue *api.FlowQueue) error {
	// Open command stream via GRPC
	stream, err := grpcClient.OpenCommandStream(context.Background())
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.Unavailable {
			return ErrServerUnavailable
		} else {
			return err
		}
	}

	// Check the containers every 1sec and send them back to the GUI for display in the containers dialog
	// Send-Containers go routine
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	go func() {
		for {
			<-ticker.C

			containers, err := listener.GetAllContainers()
			if err != nil {
				fmt.Println("[ERROR] GetAllContainers()", err)
				time.Sleep(250 * time.Millisecond)
				continue
			}

			apiContainers := convertContainersGUIToAPI(containers)
			ctx2, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			// fmt.Println("[GRPC] sending", len(apiContainers.Containers), "containers")
			grpcClient.SendContainersObserved(ctx2, &apiContainers)
		}
	}()

	// Send a NooP to the stream so the server send back the settings
	stream.Send(&api.AgentStarted{Version: version})
	fmt.Println("[GRPC] sent NooP to command stream")
	// NOTE: This seems to block the entire thing if it doesn't receive the set_settings message from the server
	for {
		// Recieve on the stream
		resp, err := stream.Recv()
		if err != nil {
			stream.CloseSend()

			if s, ok := status.FromError(err); ok && s.Code() == codes.Unavailable {
				return ErrServerUnavailable
			}
			if err == io.EOF {
				continue
			}
		}
		if resp == nil {
			continue
		}
		if resp != nil && resp.Type == "set_settings" {
			fmt.Println("[GRPC] received container_ids:", resp.Settings.ContainerIds)
			listener.SetContainers(resp.Settings.ContainerIds)

			fmt.Println("[GRPC] done setting container_ids")
		}
	}
}

func getKernelVersionMajor() int {
	var info sysinfo.SysInfo

	info.GetSysInfo()
	majorVersionStr := string(info.Kernel.Release[0])

	majorVersion, err := strconv.Atoi(majorVersionStr)
	if err != nil {
		fmt.Println("WARNING - could not get linux kernel version. Assuming 5. error:", err)
		majorVersion = 5
	}

	return majorVersion
}

func convertContainersGUIToAPI(containers []docker.ContainerGUI) api.Containers {
	apiContainers := []*api.Container{}

	for _, container := range containers {
		apiContainer := api.Container{
			Id:     container.ID,
			Image:  container.Image,
			Ip:     container.IP,
			Name:   container.Name,
			Status: container.Status,
		}
		apiContainers = append(apiContainers, &apiContainer)
	}

	return api.Containers{Containers: apiContainers}
}

func isMounted(mountPoint string) bool {
	info, err := os.Stat(mountPoint)
	if err != nil {
		fmt.Printf("Error checking mount point: %v\n", err)
		return false
	}
	// Check if the mount point is a directory
	return info.IsDir()
}
