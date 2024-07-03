package sockets_test

import (
	"github.com/evanrolfe/trayce_agent/internal/events"
	"github.com/evanrolfe/trayce_agent/internal/sockets"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("SocketHTTP1.1", func() {
	event1Payload, _ := hexDumpToBytes(event1)
	event2Payload, _ := hexDumpToBytes(event2)

	event5Payload, _ := hexDumpToBytes(event5)
	event6Payload, _ := hexDumpToBytes(event6)

	event7Payload, _ := hexDumpToBytes(event7)
	event8Payload, _ := hexDumpToBytes(event8)
	event9Payload, _ := hexDumpToBytes(event9)
	event10Payload, _ := hexDumpToBytes(event10)
	event11Payload, _ := hexDumpToBytes(event11)
	event12Payload, _ := hexDumpToBytes(event12)
	event13Payload, _ := hexDumpToBytes(event13)

	Context("Receiving a Connect, Data (request) events", Ordered, func() {
		var flows []*sockets.Flow
		payloads := [][]byte{
			event1Payload,
		}

		BeforeAll(func() {
			socket := sockets.NewSocketHttp11(&events.ConnectEvent{
				PID:  123,
				TID:  123,
				FD:   5,
				IP:   2130706433,
				Port: 80,
			})
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})

			for _, payload := range payloads {
				socket.ProcessDataEvent(&events.DataEvent{
					PID:      123,
					TID:      123,
					FD:       5,
					DataType: 1, // TODO: Use the constant from bpf_events kSSLWrite
					Data:     convertSliceToArray(payload),
					DataLen:  int32(len(payload)),
				})
			}
		})

		It("returns a flow", func() {
			Expect(flows).To(HaveLen(1))

			flow := flows[0]
			Expect(flow.RemoteAddr).To(Equal("127.0.0.1:80"))
			Expect(flow.L4Protocol).To(Equal("tcp"))
			Expect(flow.L7Protocol).To(Equal("http"))
			Expect(flow.PID).To(Equal(123))
			Expect(flow.FD).To(Equal(5))
		})

		It("the flow contains the HTTP request", func() {
			flow := flows[0]
			Expect(flow.Request).To(Equal(event1Payload))
			Expect(flow.Response).To(BeNil())
		})
	})

	Context("Receiving a Connect, Data (request), Data (response) events", Ordered, func() {
		var flows []*sockets.Flow
		payloads := [][]byte{
			event1Payload,
			event2Payload,
		}

		BeforeAll(func() {
			socket := sockets.NewSocketHttp11(&events.ConnectEvent{
				PID:  123,
				TID:  123,
				FD:   5,
				IP:   2130706433,
				Port: 80,
			})
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})

			for _, payload := range payloads {
				socket.ProcessDataEvent(&events.DataEvent{
					PID:      123,
					TID:      123,
					FD:       5,
					DataType: 1, // TODO: Use the constant from bpf_events kSSLWrite
					Data:     convertSliceToArray(payload),
					DataLen:  int32(len(payload)),
				})
			}
		})

		It("returns two flows", func() {
			Expect(flows).To(HaveLen(2))

			for _, flow := range flows {
				Expect(flow.RemoteAddr).To(Equal("127.0.0.1:80"))
				Expect(flow.L4Protocol).To(Equal("tcp"))
				Expect(flow.L7Protocol).To(Equal("http"))
				Expect(flow.PID).To(Equal(123))
				Expect(flow.FD).To(Equal(5))
			}
		})

		It("the first flow contains an HTTP request", func() {
			flow := flows[0]
			Expect(flow.Request).To(Equal(event1Payload))
			Expect(flow.Response).To(BeNil())
		})

		It("the second flow contains an HTTP request and response", func() {
			Expect(flows[1].Request).To(BeNil())
			Expect(flows[1].Response).To(Equal(event2Payload))
		})
	})

	Context("Receiving a Connect, Data (request), Data (response) events (scenario 2)", Ordered, func() {
		var flows []*sockets.Flow
		payloads := [][]byte{
			event5Payload,
			event6Payload,
		}

		BeforeAll(func() {
			socket := sockets.NewSocketHttp11(&events.ConnectEvent{
				PID:  123,
				TID:  123,
				FD:   5,
				IP:   2130706433,
				Port: 80,
			})
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})

			for _, payload := range payloads {
				socket.ProcessDataEvent(&events.DataEvent{
					PID:      123,
					TID:      123,
					FD:       5,
					DataType: 1, // TODO: Use the constant from bpf_events kSSLWrite
					Data:     convertSliceToArray(payload),
					DataLen:  int32(len(payload)),
				})
			}
		})
		It("returns two flows", func() {
			Expect(flows).To(HaveLen(2))

			for _, flow := range flows {
				Expect(flow.RemoteAddr).To(Equal("127.0.0.1:80"))
				Expect(flow.L4Protocol).To(Equal("tcp"))
				Expect(flow.L7Protocol).To(Equal("http"))
				Expect(flow.PID).To(Equal(123))
				Expect(flow.FD).To(Equal(5))
			}
		})

		It("the first flow contains an HTTP request", func() {
			flow := flows[0]
			Expect(flow.Request).To(Equal(event5Payload))
			Expect(flow.Response).To(BeNil())
		})

		It("the second flow contains an HTTP request and response", func() {
			Expect(flows[1].Request).To(BeNil())
			Expect(flows[1].Response).To(Equal(event6Payload[:1066])) // without the trailing zeroes
		})
	})

	Context("Receiving a Connect, Data (request), Data (response) events (chunked) from Go", Ordered, func() {
		var flows []*sockets.Flow
		payloads := [][]byte{
			event8Payload,
			event9Payload,
			event10Payload,
			event11Payload,
			event12Payload,
			event13Payload,
		}

		BeforeAll(func() {
			socket := sockets.NewSocketHttp11(&events.ConnectEvent{
				PID:  123,
				TID:  123,
				FD:   5,
				IP:   2130706433,
				Port: 80,
			})
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})

			// Request event
			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 7, // goTlsWrite
				Data:     convertSliceToArray(event7Payload),
				DataLen:  int32(len(event7Payload)),
			})

			// Response events
			for _, payload := range payloads {
				socket.ProcessDataEvent(&events.DataEvent{
					PID:      123,
					TID:      123,
					FD:       5,
					DataType: 6, // goTlsRead
					Data:     convertSliceToArray(payload),
					DataLen:  int32(len(payload)),
				})
			}
		})

		It("returns two flows", func() {
			Expect(flows).To(HaveLen(2))

			for _, flow := range flows {
				Expect(flow.RemoteAddr).To(Equal("127.0.0.1:80"))
				Expect(flow.L4Protocol).To(Equal("tcp"))
				Expect(flow.L7Protocol).To(Equal("http"))
				Expect(flow.PID).To(Equal(123))
				Expect(flow.FD).To(Equal(5))
			}
		})

		It("the first flow contains an HTTP request", func() {
			flow := flows[0]
			Expect(flow.Request).To(Equal(event7Payload))
			Expect(flow.Response).To(BeNil())
		})

		It("the second flow contains an HTTP request and response", func() {
			Expect(flows[1].Request).To(BeNil())
			// Expect(flows[1].Response).To(Equal(event7Payload)) // without the trailing zeroes

			// fmt.Println(string(flows[1].Response))
		})
	})
})
