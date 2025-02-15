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
			socket := sockets.SocketPsql{
				Common: sockets.SocketCommon{
					SourceAddr: "172.17.0.2:1234",
					DestAddr:   "173.17.0.2:5432",
					PID:        123,
					TID:        123,
					FD:         5,
					SSL:        false,
				},
			}
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
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
			socket := sockets.SocketPsql{
				Common: sockets.SocketCommon{
					SourceAddr: "172.17.0.2:1234",
					DestAddr:   "173.17.0.2:5432",
					PID:        123,
					TID:        123,
					FD:         5,
					SSL:        false,
				},
			}
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
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
			Expect(query.Query).To(Equal(`SELECT "things".* FROM "things"`))
			Expect(len(query.Params)).To(Equal(0))
		})
	})

	Context("Receiving events from a Postgres query & response 3", Ordered, func() {
		flows := []*sockets.Flow{}

		// Request payloads
		event1Payload, _ := hexDumpToBytes(psql3QueryEvent1)
		event2Payload, _ := hexDumpToBytes(psql3QueryEvent2)
		event3Payload, _ := hexDumpToBytes(psql3QueryEvent3)
		event4Payload, _ := hexDumpToBytes(psql3QueryEvent4)
		event5Payload, _ := hexDumpToBytes(psql3QueryEvent5)
		event6Payload, _ := hexDumpToBytes(psql3QueryEvent6)

		BeforeAll(func() {
			socket := sockets.SocketPsql{
				Common: sockets.SocketCommon{
					SourceAddr: "172.17.0.2:1234",
					DestAddr:   "173.17.0.2:5432",
					PID:        123,
					TID:        123,
					FD:         5,
					SSL:        false,
				},
			}
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
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
				DataType: 1, // kprobe/sendto
				Data:     convertSliceToArray(event2Payload),
				DataLen:  int32(len(event2Payload)),
			})
			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 0, // kprobe/recv
				Data:     convertSliceToArray(event3Payload),
				DataLen:  int32(len(event3Payload)),
			})
			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 1, // kprobe/sendto
				Data:     convertSliceToArray(event4Payload),
				DataLen:  int32(len(event4Payload)),
			})
			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 0, // kprobe/recv
				Data:     convertSliceToArray(event5Payload),
				DataLen:  int32(len(event5Payload)),
			})
			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 1, // kprobe/sendto
				Data:     convertSliceToArray(event6Payload),
				DataLen:  int32(len(event6Payload)),
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

			Expect(query.Query).To(ContainSubstring(`SELECT id, name, quantity, price, created_at FROM things WHERE id <> $1 AND name <> $2`))
			Expect(query.Params).To(Equal([]string{"123", "hello world"}))
		})

		It("returns a response flow", func() {
			Expect(flows).To(HaveLen(2))
			resp := flows[1].Response.(*sockets.PSQLResponse)

			Expect(len(resp.Rows)).To(Equal(3))

			Expect(resp.Rows[0][0]).To(Equal("1"))
			Expect(resp.Rows[0][1]).To(Equal("Widget"))
			Expect(resp.Rows[0][2]).To(Equal("5"))
			Expect(resp.Rows[0][3]).To(Equal("19.99"))
			Expect(resp.Rows[0][4]).To(Equal("2025-02-09 14:16:25.616034"))

			Expect(resp.Rows[1][0]).To(Equal("2"))
			Expect(resp.Rows[1][1]).To(Equal("Gadget"))
			Expect(resp.Rows[1][2]).To(Equal("10"))
			Expect(resp.Rows[1][3]).To(Equal("5.49"))
			Expect(resp.Rows[1][4]).To(Equal("2025-02-09 14:16:25.616034"))

			Expect(resp.Rows[2][0]).To(Equal("3"))
			Expect(resp.Rows[2][1]).To(Equal("Doodah"))
			Expect(resp.Rows[2][2]).To(Equal("3"))
			Expect(resp.Rows[2][3]).To(Equal("99.99"))
			Expect(resp.Rows[2][4]).To(Equal("2025-02-09 14:16:25.616034"))
		})
	})

	Context("Receiving a named query and response", Ordered, func() {
		flows := []*sockets.Flow{}

		// Request payloads
		event1Payload, _ := hexDumpToBytes(psql1NamedQueryEvent1)
		event2Payload, _ := hexDumpToBytes(psql1NamedQueryEvent2)
		event3Payload, _ := hexDumpToBytes(psql1NamedQueryEvent3)
		event4Payload, _ := hexDumpToBytes(psql1NamedQueryEvent4)

		BeforeAll(func() {
			socket := sockets.SocketPsql{
				Common: sockets.SocketCommon{
					SourceAddr: "172.17.0.2:1234",
					DestAddr:   "173.17.0.2:5432",
					PID:        123,
					TID:        123,
					FD:         5,
					SSL:        false,
				},
			}
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})
			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 1, // kprobe/sendto
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
		})

		It("returns a request flow", func() {
			Expect(len(flows)).To(Equal(2))

			for _, flow := range flows {
				Expect(flow.SourceAddr).To(Equal("172.17.0.2:1234"))
				Expect(flow.DestAddr).To(Equal("173.17.0.2:5432"))
				Expect(flow.L4Protocol).To(Equal("tcp"))
				Expect(flow.L7Protocol).To(Equal("psql"))
				Expect(flow.PID).To(Equal(123))
				Expect(flow.FD).To(Equal(5))
			}

			query := flows[0].Request.(*sockets.PSQLQuery)

			Expect(query.Query).To(ContainSubstring(`PREPARED STATEMENT`))
			Expect(query.Params).To(Equal([]string{"4", "1"}))
		})

		It("returns a response flow", func() {
			Expect(flows).To(HaveLen(2))
			resp := flows[1].Response.(*sockets.PSQLResponse)

			Expect(len(resp.Rows)).To(Equal(1))

			Expect(resp.Rows[0][0]).To(Equal("4"))
			Expect(resp.Rows[0][1]).To(Equal("asdfafdsx"))
			Expect(resp.Rows[0][2]).To(Equal("1"))
			Expect(resp.Rows[0][3]).To(Equal("0"))
			Expect(resp.Rows[0][4]).To(Equal("2025-02-05 09:46:42.686927"))
		})
	})
})
