package sockets_test

import (
	"github.com/evanrolfe/trayce_agent/internal/events"
	"github.com/evanrolfe/trayce_agent/internal/sockets"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("SocketPsql", func() {
	Context("Receiving events from a Postgres connection, prepared query & response", Ordered, func() {
		flows := []*sockets.Flow{}

		// Request payloads
		event1Payload, _ := hexDumpToBytes(psqlPrepEvent1)
		event2Payload, _ := hexDumpToBytes(psqlPrepEvent2)
		event3Payload, _ := hexDumpToBytes(psqlPrepEvent3)
		event4Payload, _ := hexDumpToBytes(psqlPrepEvent4)
		event5Payload, _ := hexDumpToBytes(psqlPrepEvent5)

		BeforeAll(func() {
			socket := sockets.NewSocketPsql(&events.ConnectEvent{
				PID:        123,
				TID:        123,
				FD:         5,
				SourceHost: 33558956,
				SourcePort: 1234,
				DestHost:   0,
				DestPort:   0,
			})
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})

			socket.ProcessGetsocknameEvent(&events.GetsocknameEvent{
				PID:  111,
				TID:  111,
				FD:   5,
				Host: 33558957,
				Port: 5432,
			})

			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 0, // kprobe/recv
				Data:     convertSliceToArray(event1Payload),
				DataLen:  int32(len(event1Payload)),
			})
			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 0, // kprobe/recv
				Data:     convertSliceToArray(event2Payload),
				DataLen:  int32(len(event2Payload)),
			})
			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 1, // kprobe/sendto
				Data:     convertSliceToArray(event3Payload),
				DataLen:  int32(len(event3Payload)),
			})
			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 0, // kprobe/recv
				Data:     convertSliceToArray(event4Payload),
				DataLen:  int32(len(event4Payload)),
			})
			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 1, // kprobe/sendto
				Data:     convertSliceToArray(event5Payload),
				DataLen:  int32(len(event5Payload)),
			})
		})

		It("returns a request flow", func() {
			Expect(flows).To(HaveLen(2))

			for _, flow := range flows {
				Expect(flow.SourceAddr).To(Equal("172.17.0.2:1234"))
				Expect(flow.DestAddr).To(Equal("173.17.0.2:5432"))
				Expect(flow.L4Protocol).To(Equal("tcp"))
				Expect(flow.L7Protocol).To(Equal("psql"))
				Expect(flow.PID).To(Equal(123))
				Expect(flow.FD).To(Equal(5))
			}

			query := flows[0].Request.(*sockets.PSQLQuery)
			// TODO: Trim the trailing null bytes from the query string
			Expect(query.Query).To(ContainSubstring("SELECT id, name, quantity, price, created_at FROM things WHERE id = $1 AND name = $2"))
			Expect(len(query.Params)).To(Equal(2))
			Expect(query.Params[0]).To(Equal("123"))
			Expect(query.Params[1]).To(Equal("hello world"))
		})
	})

	Context("Receiving events from a Postgres connection query & response 2", Ordered, func() {
		flows := []*sockets.Flow{}

		// Request payloads
		event1Payload, _ := hexDumpToBytes(psqlQueryEvent1)
		event2Payload, _ := hexDumpToBytes(psqlQueryEvent2)
		event3Payload, _ := hexDumpToBytes(psqlQueryEvent3)

		BeforeAll(func() {
			socket := sockets.NewSocketPsql(&events.ConnectEvent{
				PID:        123,
				TID:        123,
				FD:         5,
				SourceHost: 33558956,
				SourcePort: 1234,
				DestHost:   0,
				DestPort:   0,
			})
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})

			socket.ProcessGetsocknameEvent(&events.GetsocknameEvent{
				PID:  111,
				TID:  111,
				FD:   5,
				Host: 33558957,
				Port: 5432,
			})

			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 0, // kprobe/recv
				Data:     convertSliceToArray(event1Payload),
				DataLen:  int32(len(event1Payload)),
			})
			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 0, // kprobe/recv
				Data:     convertSliceToArray(event2Payload),
				DataLen:  int32(len(event2Payload)),
			})
			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 1, // kprobe/sendto
				Data:     convertSliceToArray(event3Payload),
				DataLen:  int32(len(event3Payload)),
			})
		})

		It("returns a request flow", func() {
			Expect(flows).To(HaveLen(2))

			for _, flow := range flows {
				Expect(flow.SourceAddr).To(Equal("172.17.0.2:1234"))
				Expect(flow.DestAddr).To(Equal("173.17.0.2:5432"))
				Expect(flow.L4Protocol).To(Equal("tcp"))
				Expect(flow.L7Protocol).To(Equal("psql"))
				Expect(flow.PID).To(Equal(123))
				Expect(flow.FD).To(Equal(5))
			}

			query := flows[0].Request.(*sockets.PSQLQuery)
			// TODO: Trim the trailing null bytes from the query string
			Expect(query.Query).To(ContainSubstring(`SELECT "things".* FROM "things"`))
			Expect(len(query.Params)).To(Equal(0))
		})
	})

})
