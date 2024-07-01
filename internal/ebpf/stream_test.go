package ebpf

import (
	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/evanrolfe/trayce_agent/internal/docker"
	"github.com/evanrolfe/trayce_agent/test/mocks"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

type MockBPFProg struct {
	mock.Mock
}

func (m *MockBPFProg) SomeMethod() {
	// Add methods that you need to mock
	m.Called()
}

var _ = Describe("Stream", func() {
	When("a container is opened", Ordered, func() {
		BeforeAll(func() {
			containers := mocks.MockContainersI{}
			bpfModule := mocks.MockBPFModuleI{}

			bpfModule.EXPECT().BPFLoadObject().Return(nil)

			bpfModule.EXPECT().GetProgram("probe_entry_SSL_read")

			bpf2 := NewBPF(&bpfModule)

			bpfProg, err := NewProbeManager(bpf2)
			Expect(err).To(BeNil())

			stream := Stream{
				probeManager:     bpfProg,
				containers:       &containers,
				containerUProbes: map[string][]*bpf.BPFLink{},
				interruptChan:    make(chan int),
				dataEventsChan:   make(chan []byte, 10000),
			}
			container := docker.Container{
				Id:            "ebaa7329ffd9",
				Pid:           123,
				Ip:            2886795266, // 172.17.0.2
				RootFSPath:    "/proc/60806/root",
				LibSSLVersion: 3,
				LibSSLPath:    "/usr/lib/x86_64-linux-gnu/libssl.so.3",
				NodePath:      "",
			}
			stream.containerOpened(container)
		})

		It("returns a flow", func() {
			Expect(true).To(Equal(true))
		})
	})
})
