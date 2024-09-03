package ebpf

import (
	"testing"

	"github.com/aquasecurity/libbpfgo"
	"github.com/evanrolfe/trayce_agent/internal/docker"
	"github.com/evanrolfe/trayce_agent/test/mocks"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

func TestEbpf(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ebpf suite")
}

var _ = Describe("Stream", func() {
	var (
		container1 = docker.Container{
			ID:            "ebaa7329ffd9",
			PID:           123,
			IP:            2886795266, // 172.17.0.2
			RootFSPath:    "/proc/60806/root",
			LibSSLVersion: 3,
			LibSSLPath:    "/proc/60806/root/usr/lib/x86_64-linux-gnu/libssl.so.3",
			NodePath:      "",
		}
		container2 = docker.Container{
			ID:            "576fe4e7985d",
			PID:           123,
			IP:            2886795267, // 172.17.0.3
			RootFSPath:    "/proc/50001/root",
			LibSSLVersion: 3,
			LibSSLPath:    "/proc/50001/root/usr/lib/x86_64-linux-gnu/libssl.so.3",
			NodePath:      "",
		}
		proc1 = docker.Proc{
			PID:           uint32(123),
			ContainerId:   container1.ID,
			ExecPath:      "/home/myserver",
			LibSSLVersion: 3,
			LibSSLPath:    container1.LibSSLPath,
		}
		proc2 = docker.Proc{
			PID:           uint32(124),
			ContainerId:   container2.ID,
			ExecPath:      "/home/apache",
			LibSSLVersion: 3,
			LibSSLPath:    container2.LibSSLPath,
		}
		proc3 = docker.Proc{
			PID:           uint32(125),
			ContainerId:   container1.ID,
			ExecPath:      "/home/myserver", // Important that this has the same path as proc1, but different PID
			LibSSLVersion: 3,
			LibSSLPath:    container1.LibSSLPath,
		}
	)

	mocksForContainerOpen := func(bpf *mocks.MockBPFI, container docker.Container) []*libbpfgo.BPFLink {
		probes := []*libbpfgo.BPFLink{
			&libbpfgo.BPFLink{},
			&libbpfgo.BPFLink{},
			&libbpfgo.BPFLink{},
			&libbpfgo.BPFLink{},
			&libbpfgo.BPFLink{},
			&libbpfgo.BPFLink{},
			&libbpfgo.BPFLink{},
			&libbpfgo.BPFLink{},
		}

		bpf.EXPECT().AttachUProbe("probe_entry_SSL_read", "SSL_read", container.LibSSLPath).Return(probes[0], nil)
		bpf.EXPECT().AttachURetProbe("probe_ret_SSL_read", "SSL_read", container.LibSSLPath).Return(probes[1], nil)
		bpf.EXPECT().AttachUProbe("probe_entry_SSL_read_ex", "SSL_read_ex", container.LibSSLPath).Return(probes[2], nil)
		bpf.EXPECT().AttachURetProbe("probe_ret_SSL_read_ex", "SSL_read_ex", container.LibSSLPath).Return(probes[3], nil)
		bpf.EXPECT().AttachUProbe("probe_entry_SSL_write", "SSL_write", container.LibSSLPath).Return(probes[4], nil)
		bpf.EXPECT().AttachURetProbe("probe_ret_SSL_write", "SSL_write", container.LibSSLPath).Return(probes[5], nil)
		bpf.EXPECT().AttachUProbe("probe_entry_SSL_write_ex", "SSL_write_ex", container.LibSSLPath).Return(probes[6], nil)
		bpf.EXPECT().AttachURetProbe("probe_ret_SSL_write_ex", "SSL_write_ex", container.LibSSLPath).Return(probes[7], nil)

		return probes
	}

	mocksForProcOpen := func(bpf *mocks.MockBPFI, proc docker.Proc) []*libbpfgo.BPFLink {
		probes := []*libbpfgo.BPFLink{
			&libbpfgo.BPFLink{},
			&libbpfgo.BPFLink{},
			&libbpfgo.BPFLink{},
		}
		bpf.EXPECT().AttachGoUProbe("probe_entry_go_tls_write", "", "crypto/tls.(*Conn).Write", proc.ExecPath).Return([]*libbpfgo.BPFLink{probes[0]}, nil)
		bpf.EXPECT().AttachGoUProbe("probe_entry_go_tls_read", "probe_exit_go_tls_read", "crypto/tls.(*Conn).Read", proc.ExecPath).Return([]*libbpfgo.BPFLink{probes[1], probes[2]}, nil)

		return probes
	}

	When("a container is opened, then a proc opened, then a proc closed", Ordered, func() {
		var (
			attachedGoProbesProc1 []*libbpfgo.BPFLink
			destroyedUprobes      []*libbpfgo.BPFLink
		)
		BeforeAll(func() {
			containers := mocks.MockContainersI{}
			bpf := mocks.MockBPFI{}
			bpf.EXPECT().LoadProgram().Return(nil)

			// Mocks
			mocksForContainerOpen(&bpf, container1)
			attachedGoProbesProc1 = mocksForProcOpen(&bpf, proc1)

			bpf.EXPECT().DestroyProbe(mock.AnythingOfType("*libbpfgo.BPFLink")).
				RunAndReturn(func(probe *libbpfgo.BPFLink) error {
					destroyedUprobes = append(destroyedUprobes, probe)
					return nil
				})

			probeManager, err := NewProbeManager(&bpf)
			Expect(err).To(BeNil())

			// Subject under test
			stream := NewStream(&containers, probeManager)
			stream.containerOpened(container1)
			stream.procOpened(proc1)
			stream.procClosed(proc1)
		})

		It("destroys the Go uprobes attached to proc 1", func() {
			Expect(len(destroyedUprobes)).To(Equal(3))
			Expect(destroyedUprobes).To(ContainElements(attachedGoProbesProc1))
		})
	})

	When("a container is opened, two procs opened (with same binpath), then a proc closed", Ordered, func() {
		var (
			attachedGoProbesProc3 []*libbpfgo.BPFLink
			destroyedUprobes      []*libbpfgo.BPFLink
		)
		BeforeAll(func() {
			containers := mocks.MockContainersI{}
			bpf := mocks.MockBPFI{}
			bpf.EXPECT().LoadProgram().Return(nil)

			// Mocks
			_ = mocksForContainerOpen(&bpf, container1)
			_ = mocksForProcOpen(&bpf, proc1)
			attachedGoProbesProc3 = mocksForProcOpen(&bpf, proc3)

			bpf.EXPECT().DestroyProbe(mock.AnythingOfType("*libbpfgo.BPFLink")).
				RunAndReturn(func(probe *libbpfgo.BPFLink) error {
					destroyedUprobes = append(destroyedUprobes, probe)
					return nil
				})

			// Subject under test
			probeManager, err := NewProbeManager(&bpf)
			Expect(err).To(BeNil())

			stream := NewStream(&containers, probeManager)
			stream.containerOpened(container1)
			stream.procOpened(proc1)
			stream.procOpened(proc3)
			stream.procClosed(proc3)
		})

		It("destroys the Go uprobes attached to proc 3", func() {
			Expect(len(destroyedUprobes)).To(Equal(3))
			Expect(destroyedUprobes).To(ContainElements(attachedGoProbesProc3))
		})
	})

	When("a container is opened, then a proc opened, then the container is closed and proc clsoed", Ordered, func() {
		var (
			attachedGoProbes     []*libbpfgo.BPFLink
			attachedLibSSLProbes []*libbpfgo.BPFLink
			destroyedUprobes     []*libbpfgo.BPFLink
		)
		BeforeAll(func() {
			containers := mocks.MockContainersI{}
			bpf := mocks.MockBPFI{}
			bpf.EXPECT().LoadProgram().Return(nil)

			// Mocks
			attachedLibSSLProbes = mocksForContainerOpen(&bpf, container1)
			attachedGoProbes = mocksForProcOpen(&bpf, proc1)

			bpf.EXPECT().DestroyProbe(mock.AnythingOfType("*libbpfgo.BPFLink")).
				RunAndReturn(func(probe *libbpfgo.BPFLink) error {
					destroyedUprobes = append(destroyedUprobes, probe)
					return nil
				})

			// Subject under test
			probeManager, err := NewProbeManager(&bpf)
			Expect(err).To(BeNil())

			stream := NewStream(&containers, probeManager)
			stream.containerOpened(container1)
			stream.procOpened(proc1)
			stream.containerClosed(container1)
			stream.procClosed(proc1)
		})

		It("destroys the libssl uprobes attached", func() {
			Expect(len(destroyedUprobes)).To(Equal(11))
			Expect(destroyedUprobes).To(ContainElements(attachedLibSSLProbes))
		})

		It("destroys the Go uprobes attached to the proc", func() {
			Expect(destroyedUprobes).To(ContainElements(attachedGoProbes))
		})
	})

	When("two containers are opened then one closed", Ordered, func() {
		var (
			attachedLibSSLProbes  []*libbpfgo.BPFLink
			attachedGoProbesProc1 []*libbpfgo.BPFLink
			destroyedUprobes      []*libbpfgo.BPFLink
		)

		BeforeAll(func() {
			containers := mocks.MockContainersI{}
			bpf := mocks.MockBPFI{}
			bpf.EXPECT().LoadProgram().Return(nil)

			// Mocks
			attachedLibSSLProbes = mocksForContainerOpen(&bpf, container1)
			_ = mocksForContainerOpen(&bpf, container2)

			attachedGoProbesProc1 = mocksForProcOpen(&bpf, proc1)
			_ = mocksForProcOpen(&bpf, proc2)

			bpf.EXPECT().DestroyProbe(mock.AnythingOfType("*libbpfgo.BPFLink")).
				RunAndReturn(func(probe *libbpfgo.BPFLink) error {
					destroyedUprobes = append(destroyedUprobes, probe)
					return nil
				})

			// Subject under test
			probeManager, err := NewProbeManager(&bpf)
			Expect(err).To(BeNil())

			stream := NewStream(&containers, probeManager)
			stream.containerOpened(container1)
			stream.procOpened(proc1)

			stream.containerOpened(container2)
			stream.procOpened(proc2)

			stream.containerClosed(container1)
		})

		It("destroys the libssl uprobes attached to container1", func() {
			Expect(len(destroyedUprobes)).To(Equal(11))
			Expect(destroyedUprobes).To(ContainElements(attachedLibSSLProbes))
		})

		It("destroys the Go uprobes attached to the proc1", func() {
			Expect(destroyedUprobes).To(ContainElements(attachedGoProbesProc1))
		})
	})
})
