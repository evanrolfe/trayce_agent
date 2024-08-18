package sockets_test

import (
	"encoding/hex"
	"fmt"

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

	gzip1Payload, _ := hexDumpToBytes(gzipEvent1)
	gzip2Payload, _ := hexDumpToBytes(gzipEvent2)

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

	// In HTTPS we get both the encrypted & decrypted versions of the same event sent, so we have to ensure only the
	// encrypted one is processed
	Context("Receiving a Connect, TLS Data (request), Non-TLS Data, TLS Data (response) events", Ordered, func() {
		var flows []*sockets.Flow
		randomPayload := []byte{0x00, 0x00, 0x26, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01, 0x88, 0x5f, 0x87, 0x49, 0x7c, 0xa5, 0x8a, 0xe8, 0x19, 0xaa, 0x5c, 0x02, 0x31, 0x33, 0x61, 0x96, 0xd0, 0x7a, 0xbe, 0x94, 0x03, 0x8a, 0x68, 0x1f, 0xa5, 0x04, 0x01, 0x34, 0xa0, 0x5c, 0xb8, 0xc8, 0xae, 0x34, 0x15, 0x31, 0x68, 0xdf}

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

			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 0, // kSSLRead
				Data:     convertSliceToArray(event1Payload),
				DataLen:  int32(len(event1Payload)),
			})
			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 2, // kRead
				Data:     convertSliceToArray(randomPayload),
				DataLen:  int32(len(randomPayload)),
			})
			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 1, // kSSLWrite
				Data:     convertSliceToArray(event2Payload),
				DataLen:  int32(len(event2Payload)),
			})
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

			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 2, // kRead
				Data:     convertSliceToArray(event5Payload),
				DataLen:  int32(len(event5Payload)),
			})
			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 3, // kWrite
				Data:     convertSliceToArray(event6Payload),
				DataLen:  int32(len(event6Payload)),
			})
			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 3, // kWrite
				Data:     convertSliceToArray(event13Payload),
				DataLen:  int32(len(event13Payload)),
			})
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
			Expect(len(flows[1].Response)).To(Equal(1060))
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

	Context("Receiving a Connect, Data (request), Data (response) events (gzip'd)", Ordered, func() {
		var flows []*sockets.Flow

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
				Data:     convertSliceToArray(gzip1Payload),
				DataLen:  int32(len(gzip1Payload)),
			})

			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 6, // goTlsRead
				Data:     convertSliceToArray(gzip2Payload),
				DataLen:  int32(len(gzip2Payload)),
			})
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
			Expect(flow.Request).To(Equal(gzip1Payload))
			Expect(flow.Response).To(BeNil())
		})

		It("the second flow contains an HTTP request and response", func() {
			Expect(flows[1].Request).To(BeNil())
			Expect(flows[1].Response).ToNot(BeNil())

			fmt.Println("=====================>\n", hex.Dump(flows[1].Response))
			// Expect(flows[1].Response).To(Equal(event7Payload)) // without the trailing zeroes

			// fmt.Println(string(flows[1].Response))
		})
	})
})
