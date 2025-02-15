package sockets_test

import (
	"github.com/evanrolfe/trayce_agent/internal/events"
	"github.com/evanrolfe/trayce_agent/internal/sockets"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("SocketMap", func() {
	event1Payload, _ := hexDumpToBytes(event1)
	event2Payload, _ := hexDumpToBytes(event2)

	Context("[HTTP1] Receiving a Connect, Data (request), Data (response) events", Ordered, func() {
		var socketsMap *sockets.SocketMap
		var flows []*sockets.Flow

		BeforeAll(func() {
			socketsMap = sockets.NewSocketMap()
			socketsMap.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})
			socketsMap.ProcessDataEvent(events.DataEvent{
				PID:        123,
				TID:        123,
				FD:         5,
				DataType:   1,
				Data:       convertSliceToArray(event1Payload),
				DataLen:    int32(len(event1Payload)),
				SourceHost: 33558956,
				SourcePort: 1234,
				DestHost:   16777343,
				DestPort:   80,
			})
			socketsMap.ProcessDataEvent(events.DataEvent{
				PID:        123,
				TID:        123,
				FD:         5,
				DataType:   0,
				Data:       convertSliceToArray(event2Payload),
				DataLen:    int32(len(event2Payload)),
				SourceHost: 33558956,
				SourcePort: 1234,
				DestHost:   16777343,
				DestPort:   80,
			})
		})

		It("returns two flows", func() {
			Expect(flows).To(HaveLen(2))

			for _, flow := range flows {
				// Expect(flow.RemoteAddr).To(Equal("127.0.0.1:80"))
				Expect(flow.L4Protocol).To(Equal("tcp"))
				Expect(flow.L7Protocol).To(Equal("http"))
				Expect(flow.PID).To(Equal(123))
				Expect(flow.FD).To(Equal(5))
			}
		})

		It("the first flow contains an HTTP request", func() {
			flow := flows[0]
			Expect(flow.Request).ToNot(BeNil())
			req, ok := flow.Request.(*sockets.HTTPRequest)
			Expect(ok).To(BeTrue())

			Expect(req.Method).To(Equal("GET"))
			Expect(req.Path).To(Equal("/"))
			Expect(req.HttpVersion).To(Equal("1.1"))
			Expect(req.Host).To(Equal("localhost:4122"))

			Expect(flow.Response).To(BeNil())
		})

		It("the second flow contains an HTTP request and response", func() {
			Expect(flows[1].Request).To(BeNil())
			resp, ok := flows[1].Response.(*sockets.HTTPResponse)
			Expect(ok).To(BeTrue())

			Expect(resp.Status).To(Equal(200))
			Expect(resp.HttpVersion).To(Equal("1.1"))
			Expect(resp.Headers["Content-Type"]).To(Equal([]string{"text/plain"}))
			Expect(resp.Headers["Content-Length"]).To(Equal([]string{"13"}))
			Expect(resp.Headers["Date"]).To(Equal([]string{"Fri, 15 Sep 2023 07:18:18 GMT"}))
			Expect(resp.Payload).To(Equal([]byte("Hello world.\n")))
		})
	})

	Context("[HTTP2] Receiving a Connect, Data", Ordered, func() {
		var socketsMap *sockets.SocketMap
		var flows []*sockets.Flow
		payloads := [][]byte{
			// uprobe/go_tls_read
			{0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a, 0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a},
			{0x00, 0x00, 0x12, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00},
			{0x00, 0x03, 0x00, 0x00, 0x00, 0x64, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00},
			{0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00},
			{0x01, 0xff, 0x00, 0x01},
			{0x00, 0x00, 0x31, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01},
			{0x83, 0x84, 0x87, 0x41, 0x8b, 0x0b, 0xa2, 0x5c, 0x2e, 0xae, 0x05, 0xd9, 0xb8, 0xd0, 0x44, 0xcf, 0x7a, 0x88, 0x25, 0xb6, 0x50, 0xc3, 0xab, 0xbc, 0x15, 0xc1, 0x53, 0x03, 0x2a, 0x2f, 0x2a, 0x5f, 0x8b, 0x1d, 0x75, 0xd0, 0x62, 0x0d, 0x26, 0x3d, 0x4c, 0x74, 0x41, 0xea, 0x0f, 0x0d, 0x02, 0x33, 0x34},
			// uprobe/go_tls_write
			{0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x01},
			// uprobe/go_tls_read
			{0x00, 0x00, 0x22, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01},
			{0x7b, 0x22, 0x6b, 0x65, 0x79, 0x31, 0x22, 0x3a, 0x22, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x31, 0x22, 0x2c, 0x20, 0x22, 0x6b, 0x65, 0x79, 0x32, 0x22, 0x3a, 0x22, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x32, 0x22, 0x7d},
			{0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00},
			// uprobe/go_tls_write
			{0x00, 0x00, 0x26, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01, 0x88, 0x5f, 0x87, 0x49, 0x7c, 0xa5, 0x8a, 0xe8, 0x19, 0xaa, 0x5c, 0x02, 0x31, 0x33, 0x61, 0x96, 0xd0, 0x7a, 0xbe, 0x94, 0x03, 0x8a, 0x68, 0x1f, 0xa5, 0x04, 0x01, 0x34, 0xa0, 0x5c, 0xb8, 0xc8, 0xae, 0x34, 0x15, 0x31, 0x68, 0xdf},
			{0x00, 0x00, 0x0d, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x2e, 0x0a},
		}

		BeforeAll(func() {
			socketsMap = sockets.NewSocketMap()
			socketsMap.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})

			for _, payload := range payloads {
				socketsMap.ProcessDataEvent(events.DataEvent{
					PID:        123,
					TID:        123,
					FD:         5,
					DataType:   1,
					Data:       convertSliceToArray(payload),
					DataLen:    int32(len(payload)),
					SourceHost: 33558956,
					SourcePort: 1234,
					DestHost:   16777343,
					DestPort:   80,
				})
			}
		})

		It("returns a request flow", func() {
			Expect(flows).To(HaveLen(2))

			flow := flows[0]
			// Expect(flow.RemoteAddr).To(Equal("127.0.0.1:80"))
			Expect(flow.L4Protocol).To(Equal("tcp"))
			Expect(flow.L7Protocol).To(Equal("http2"))
			Expect(flow.PID).To(Equal(123))
			Expect(flow.FD).To(Equal(5))

			Expect(flow.Request).ToNot(BeNil())
			Expect(flow.Response).To(BeNil())

			req, ok := flow.Request.(*sockets.HTTPRequest)
			Expect(ok).To(BeTrue())

			Expect(req.Method).To(Equal("POST"))
			Expect(req.Path).To(Equal("/"))
			Expect(req.HttpVersion).To(Equal("2"))
			Expect(req.Host).To(Equal("172.17.0.3:4123"))
			Expect(req.Headers["user-agent"]).To(Equal([]string{"curl/7.81.0"}))
			Expect(req.Headers["accept"]).To(Equal([]string{"*/*"}))
			Expect(req.Headers["content-type"]).To(Equal([]string{"application/json"}))
			Expect(req.Headers["content-length"]).To(Equal([]string{"34"}))
			Expect(req.Payload).To(Equal([]byte(`{"key1":"value1", "key2":"value2"}`)))
		})

		It("returns a response flow", func() {
			flow := flows[1]
			// Expect(flow.RemoteAddr).To(Equal("127.0.0.1:80"))
			Expect(flow.L4Protocol).To(Equal("tcp"))
			Expect(flow.L7Protocol).To(Equal("http2"))
			Expect(flow.PID).To(Equal(123))
			Expect(flow.FD).To(Equal(5))

			Expect(flow.Request).To(BeNil())
			Expect(flow.Response).ToNot(BeNil())

			resp, ok := flow.Response.(*sockets.HTTPResponse)
			Expect(ok).To(BeTrue())

			Expect(resp.Status).To(Equal(200))
			Expect(resp.HttpVersion).To(Equal("2"))
			Expect(resp.Headers["content-type"]).To(Equal([]string{"text/plain"}))
			Expect(resp.Headers["content-length"]).To(Equal([]string{"13"}))
			Expect(resp.Headers["date"]).To(Equal([]string{"Mon, 06 May 2024 16:32:41 GMT"}))
			Expect(resp.Payload).To(Equal([]byte("Hello world.\n")))
		})
	})

	Context("[Postgres] receiving events from a Postgres connection, query & response", Ordered, func() {
		event1Payload, _ := hexDumpToBytes(psqlEvent1)
		event2Payload, _ := hexDumpToBytes(psqlEvent2)
		event3Payload, _ := hexDumpToBytes(psqlEvent3)
		event4Payload, _ := hexDumpToBytes(psqlEvent4)
		event5Payload, _ := hexDumpToBytes(psqlEvent5)
		event6Payload, _ := hexDumpToBytes(psqlEvent6)
		event7Payload, _ := hexDumpToBytes(psqlEvent7)
		event8Payload, _ := hexDumpToBytes(psqlEvent8)
		event9Payload, _ := hexDumpToBytes(psqlEvent9)
		event10Payload, _ := hexDumpToBytes(psqlEvent10)
		event11Payload, _ := hexDumpToBytes(psqlEvent11)
		event12Payload, _ := hexDumpToBytes(psqlEvent12)
		event13Payload, _ := hexDumpToBytes(psqlEvent13)
		event14Payload, _ := hexDumpToBytes(psqlEvent14)
		event15Payload, _ := hexDumpToBytes(psqlEvent15)

		var socketsMap *sockets.SocketMap
		var flows []*sockets.Flow

		processReceive := func(payload []byte) {
			socketsMap.ProcessDataEvent(events.DataEvent{
				PID:        222,
				TID:        222,
				FD:         5,
				DataType:   0,
				Data:       convertSliceToArray(payload),
				DataLen:    int32(len(payload)),
				SourceHost: 33558956,
				SourcePort: 1234,
				DestHost:   16777343,
				DestPort:   80,
			})
		}
		processSend := func(payload []byte) {
			socketsMap.ProcessDataEvent(events.DataEvent{
				PID:        222,
				TID:        222,
				FD:         5,
				DataType:   1,
				Data:       convertSliceToArray(payload),
				DataLen:    int32(len(payload)),
				SourceHost: 33558956,
				SourcePort: 1234,
				DestHost:   16777343,
				DestPort:   80,
			})
		}

		BeforeAll(func() {
			socketsMap = sockets.NewSocketMap()
			socketsMap.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})

			processReceive(event1Payload)
			processReceive(event2Payload)
			processSend(event3Payload)
			processReceive(event4Payload)
			processSend(event5Payload)
			processReceive(event6Payload)
			processSend(event7Payload)
			processReceive(event8Payload)
			processSend(event9Payload)
			processReceive(event10Payload)
			processSend(event11Payload)
			processReceive(event12Payload)
			processSend(event13Payload)
			processReceive(event14Payload)
			processSend(event15Payload)
		})

		It("returns two flows", func() {
			Expect(flows).To(HaveLen(2))

			for _, flow := range flows {
				Expect(flow.SourceAddr).To(Equal("172.17.0.2:1234"))
				Expect(flow.DestAddr).To(Equal("127.0.0.1:80"))
				Expect(flow.L4Protocol).To(Equal("tcp"))
				Expect(flow.L7Protocol).To(Equal("psql"))
				Expect(flow.PID).To(Equal(222))
				Expect(flow.FD).To(Equal(5))
			}
		})

		// It("the first flow contains an HTTP request", func() {
		// 	flow := flows[0]
		// 	Expect(flow.Request).ToNot(BeNil())
		// 	req, ok := flow.Request.(*sockets.HTTPRequest)
		// 	Expect(ok).To(BeTrue())

		// 	Expect(req.Method).To(Equal("GET"))
		// 	Expect(req.Path).To(Equal("/"))
		// 	Expect(req.HttpVersion).To(Equal("1.1"))
		// 	Expect(req.Host).To(Equal("localhost:4122"))

		// 	Expect(flow.Response).To(BeNil())
		// })

		// It("the second flow contains an HTTP request and response", func() {
		// 	Expect(flows[1].Request).To(BeNil())
		// 	resp, ok := flows[1].Response.(*sockets.HTTPResponse)
		// 	Expect(ok).To(BeTrue())

		// 	Expect(resp.Status).To(Equal(200))
		// 	Expect(resp.HttpVersion).To(Equal("1.1"))
		// 	Expect(resp.Headers["Content-Type"]).To(Equal([]string{"text/plain"}))
		// 	Expect(resp.Headers["Content-Length"]).To(Equal([]string{"13"}))
		// 	Expect(resp.Headers["Date"]).To(Equal([]string{"Fri, 15 Sep 2023 07:18:18 GMT"}))
		// 	Expect(resp.Payload).To(Equal([]byte("Hello world.\n")))
		// })
	})

	Context("[Mysql] receiving events from a Mysql connection, query & response", Ordered, func() {
		event1Payload, _ := hexDumpToBytes(mysqlQueryEvent1)
		event2Payload, _ := hexDumpToBytes(mysqlQueryEvent2)
		event3Payload, _ := hexDumpToBytes(mysqlQueryEvent3)
		event4Payload, _ := hexDumpToBytes(mysqlQueryEvent4)
		event5Payload, _ := hexDumpToBytes(mysqlQueryEvent5)
		event6Payload, _ := hexDumpToBytes(mysqlQueryEvent6)
		event7Payload, _ := hexDumpToBytes(mysqlQueryEvent7)
		event8Payload, _ := hexDumpToBytes(mysqlQueryEvent8)
		event9Payload, _ := hexDumpToBytes(mysqlQueryEvent9)
		event10Payload, _ := hexDumpToBytes(mysqlQueryEvent10)
		event11Payload, _ := hexDumpToBytes(mysqlQueryEvent11)
		event12Payload, _ := hexDumpToBytes(mysqlQueryEvent12)
		event13Payload, _ := hexDumpToBytes(mysqlQueryEvent13)

		var socketsMap *sockets.SocketMap
		var flows []*sockets.Flow

		processReceive := func(payload []byte) {
			socketsMap.ProcessDataEvent(events.DataEvent{
				PID:        222,
				TID:        222,
				FD:         5,
				DataType:   0,
				Data:       convertSliceToArray(payload),
				DataLen:    int32(len(payload)),
				SourceHost: 33558956,
				SourcePort: 1234,
				DestHost:   33558957,
				DestPort:   3306,
			})
		}
		processSend := func(payload []byte) {
			socketsMap.ProcessDataEvent(events.DataEvent{
				PID:        222,
				TID:        222,
				FD:         5,
				DataType:   1,
				Data:       convertSliceToArray(payload),
				DataLen:    int32(len(payload)),
				SourceHost: 33558956,
				SourcePort: 1234,
				DestHost:   33558957,
				DestPort:   3306,
			})
		}

		BeforeAll(func() {
			socketsMap = sockets.NewSocketMap()
			socketsMap.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})
			processSend(event1Payload)
			processReceive(event2Payload)
			processSend(event3Payload)
			processReceive(event4Payload)
			processReceive(event5Payload)
			processSend(event6Payload)
			processReceive(event7Payload)
			processReceive(event8Payload)
			processSend(event9Payload)
			processReceive(event10Payload)
			processReceive(event11Payload)
			processSend(event12Payload)
			processReceive(event13Payload)
		})

		It("returns a query flow", func() {
			Expect(flows).To(HaveLen(2))

			for _, flow := range flows {
				Expect(flow.SourceAddr).To(Equal("172.17.0.2:1234"))
				Expect(flow.DestAddr).To(Equal("173.17.0.2:3306"))
				Expect(flow.L4Protocol).To(Equal("tcp"))
				Expect(flow.L7Protocol).To(Equal("mysql"))
				Expect(flow.PID).To(Equal(222))
				Expect(flow.FD).To(Equal(5))
			}

			query := flows[0].Request.(*sockets.MysqlQuery)

			Expect(query.Query).To(Equal(`SELECT id, name, quantity, price, created_at FROM things`))
			Expect(len(query.Params)).To(Equal(0))
		})

		It("returns a response flow", func() {
			Expect(flows).To(HaveLen(2))
			resp := flows[1].Response.(*sockets.MysqlResponse)

			Expect(len(resp.Rows)).To(Equal(3))

			Expect(resp.Rows[0][0]).To(Equal("1"))
			Expect(resp.Rows[0][1]).To(Equal("Widget"))
			Expect(resp.Rows[0][2]).To(Equal("5"))
			Expect(resp.Rows[0][3]).To(Equal("19.99"))
			Expect(resp.Rows[0][4]).To(Equal("2024-12-14 20:29:49.000000"))

			Expect(resp.Rows[1][0]).To(Equal("2"))
			Expect(resp.Rows[1][1]).To(Equal("Gadget"))
			Expect(resp.Rows[1][2]).To(Equal("10"))
			Expect(resp.Rows[1][3]).To(Equal("5.49"))
			Expect(resp.Rows[1][4]).To(Equal("2024-12-14 20:29:49.000000"))

			Expect(resp.Rows[2][0]).To(Equal("3"))
			Expect(resp.Rows[2][1]).To(Equal("Doodah"))
			Expect(resp.Rows[2][2]).To(Equal("3"))
			Expect(resp.Rows[2][3]).To(Equal("99.99"))
			Expect(resp.Rows[2][4]).To(Equal("2024-12-14 20:29:49.000000"))
		})
	})

	Context("[Mysql] receiving events from a Mysql query & response SSL", Ordered, func() {
		event1Payload, _ := hexDumpToBytes(mysqlQuerySSLEvent1)
		event2Payload, _ := hexDumpToBytes(mysqlQuerySSLEvent2)
		event3Payload, _ := hexDumpToBytes(mysqlQuerySSLEvent3)
		event4Payload, _ := hexDumpToBytes(mysqlQuerySSLEvent4)
		event5Payload, _ := hexDumpToBytes(mysqlQuerySSLEvent5)
		event6Payload, _ := hexDumpToBytes(mysqlQuerySSLEvent6)
		event7Payload, _ := hexDumpToBytes(mysqlQuerySSLEvent7)
		event8Payload, _ := hexDumpToBytes(mysqlQuerySSLEvent8)
		event9Payload, _ := hexDumpToBytes(mysqlQuerySSLEvent9)

		event14Payload, _ := hexDumpToBytes(mysqlQuerySSLEvent14)
		event15Payload, _ := hexDumpToBytes(mysqlQuerySSLEvent15)
		event16Payload, _ := hexDumpToBytes(mysqlQuerySSLEvent16)
		event17Payload, _ := hexDumpToBytes(mysqlQuerySSLEvent17)
		event18Payload, _ := hexDumpToBytes(mysqlQuerySSLEvent18)
		event19Payload, _ := hexDumpToBytes(mysqlQuerySSLEvent19)
		event20Payload, _ := hexDumpToBytes(mysqlQuerySSLEvent20)
		event21Payload, _ := hexDumpToBytes(mysqlQuerySSLEvent21)
		event22Payload, _ := hexDumpToBytes(mysqlQuerySSLEvent22)
		event23Payload, _ := hexDumpToBytes(mysqlQuerySSLEvent23)
		event24Payload, _ := hexDumpToBytes(mysqlQuerySSLEvent24)
		event25Payload, _ := hexDumpToBytes(mysqlQuerySSLEvent25)
		event26Payload, _ := hexDumpToBytes(mysqlQuerySSLEvent26)
		event27Payload, _ := hexDumpToBytes(mysqlQuerySSLEvent27)
		event28Payload, _ := hexDumpToBytes(mysqlQuerySSLEvent28)
		event29Payload, _ := hexDumpToBytes(mysqlQuerySSLEvent29)

		var socketsMap *sockets.SocketMap
		var flows []*sockets.Flow

		processEvent := func(payload []byte, source uint64) {
			socketsMap.ProcessDataEvent(events.DataEvent{
				PID:        222,
				TID:        222,
				FD:         5,
				DataType:   source,
				Data:       convertSliceToArray(payload),
				DataLen:    int32(len(payload)),
				SourceHost: 33558956,
				SourcePort: 1234,
				DestHost:   33558957,
				DestPort:   3306,
			})
		}

		BeforeAll(func() {
			socketsMap = sockets.NewSocketMap()
			socketsMap.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})
			processEvent(event1Payload, events.KRead)
			processEvent(event2Payload, events.KSSLRead)
			processEvent(event3Payload, events.KSSLRead)
			processEvent(event4Payload, events.KWrite)
			processEvent(event5Payload, events.KSSLWrite)
			processEvent(event6Payload, events.KSSLRead)
			processEvent(event7Payload, events.KSSLRead)
			processEvent(event8Payload, events.KSSLRead)
			processEvent(event9Payload, events.KSSLRead)

			processEvent(event14Payload, events.KSSLRead)
			processEvent(event15Payload, events.KSSLRead)
			processEvent(event16Payload, events.KSSLRead)
			processEvent(event17Payload, events.KSSLRead)
			processEvent(event18Payload, events.KSSLRead)
			processEvent(event19Payload, events.KSSLRead)
			processEvent(event20Payload, events.KSSLRead)
			processEvent(event21Payload, events.KSSLRead)
			processEvent(event22Payload, events.KSSLRead)
			processEvent(event23Payload, events.KSSLRead)
			processEvent(event24Payload, events.KSSLRead)
			processEvent(event25Payload, events.KSSLRead)
			processEvent(event26Payload, events.KSSLRead)
			processEvent(event27Payload, events.KSSLRead)
			processEvent(event28Payload, events.KSSLRead)
			processEvent(event29Payload, events.KSSLRead)
		})

		It("returns two flows", func() {
			Expect(len(flows)).To(Equal(2))

			for _, flow := range flows {
				Expect(flow.SourceAddr).To(Equal("172.17.0.2:1234"))
				Expect(flow.DestAddr).To(Equal("173.17.0.2:3306"))
				Expect(flow.L4Protocol).To(Equal("tcp"))
				Expect(flow.L7Protocol).To(Equal("mysql"))
				Expect(flow.PID).To(Equal(222))
				Expect(flow.FD).To(Equal(5))
			}

			query := flows[0].Request.(*sockets.MysqlQuery)

			Expect(query.Query).To(Equal("SELECT `things`.* FROM `things`"))
			Expect(len(query.Params)).To(Equal(0))
		})

		It("returns a response flow", func() {
			Expect(flows).To(HaveLen(2))
			resp := flows[1].Response.(*sockets.MysqlResponse)

			Expect(len(resp.Columns)).To(Equal(5))
			Expect(resp.Columns[0].Name).To(Equal("id"))
			Expect(resp.Columns[1].Name).To(Equal("name"))
			Expect(resp.Columns[2].Name).To(Equal("quantity"))
			Expect(resp.Columns[3].Name).To(Equal("price"))
			Expect(resp.Columns[4].Name).To(Equal("created_at"))

			Expect(len(resp.Rows)).To(Equal(3))

			Expect(resp.Rows[0][0]).To(Equal("1"))
			Expect(resp.Rows[0][1]).To(Equal("Widget"))
			Expect(resp.Rows[0][2]).To(Equal("5"))
			Expect(resp.Rows[0][3]).To(Equal("19.99"))
			Expect(resp.Rows[0][4]).To(Equal("2025-02-11 20:54:39.000000"))

			Expect(resp.Rows[1][0]).To(Equal("2"))
			Expect(resp.Rows[1][1]).To(Equal("Gadget"))
			Expect(resp.Rows[1][2]).To(Equal("10"))
			Expect(resp.Rows[1][3]).To(Equal("5.49"))
			Expect(resp.Rows[1][4]).To(Equal("2025-02-11 20:54:39.000000"))

			Expect(resp.Rows[2][0]).To(Equal("3"))
			Expect(resp.Rows[2][1]).To(Equal("Doodah"))
			Expect(resp.Rows[2][2]).To(Equal("3"))
			Expect(resp.Rows[2][3]).To(Equal("99.99"))
			Expect(resp.Rows[2][4]).To(Equal("2025-02-11 20:54:39.000000"))
		})
	})

	Context("[Mysql] receiving prepared query response SSL", Ordered, func() {
		event1Payload, _ := hexDumpToBytes(mysqlPreparedQuery1)
		event2Payload, _ := hexDumpToBytes(mysqlPreparedQuery2)
		event3Payload, _ := hexDumpToBytes(mysqlPreparedQuery3)
		event4Payload, _ := hexDumpToBytes(mysqlPreparedQuery4)
		event5Payload, _ := hexDumpToBytes(mysqlPreparedQuery5)
		event6Payload, _ := hexDumpToBytes(mysqlPreparedQuery6)
		event7Payload, _ := hexDumpToBytes(mysqlPreparedQuery7)
		event8Payload, _ := hexDumpToBytes(mysqlPreparedQuery8)
		event9Payload, _ := hexDumpToBytes(mysqlPreparedQuery9)
		event10Payload, _ := hexDumpToBytes(mysqlPreparedQuery10)
		event11Payload, _ := hexDumpToBytes(mysqlPreparedQuery11)
		event12Payload, _ := hexDumpToBytes(mysqlPreparedQuery12)
		event13Payload, _ := hexDumpToBytes(mysqlPreparedQuery13)
		event14Payload, _ := hexDumpToBytes(mysqlPreparedQuery14)
		event15Payload, _ := hexDumpToBytes(mysqlPreparedQuery15)
		event16Payload, _ := hexDumpToBytes(mysqlPreparedQuery16)
		event17Payload, _ := hexDumpToBytes(mysqlPreparedQuery17)
		event18Payload, _ := hexDumpToBytes(mysqlPreparedQuery18)
		event19Payload, _ := hexDumpToBytes(mysqlPreparedQuery19)
		event20Payload, _ := hexDumpToBytes(mysqlPreparedQuery20)

		var socketsMap *sockets.SocketMap
		var flows []*sockets.Flow

		processEvent := func(payload []byte, source uint64) {
			socketsMap.ProcessDataEvent(events.DataEvent{
				PID:        222,
				TID:        222,
				FD:         5,
				DataType:   source,
				Data:       convertSliceToArray(payload),
				DataLen:    int32(len(payload)),
				SourceHost: 33558956,
				SourcePort: 1234,
				DestHost:   33558957,
				DestPort:   3306,
			})
		}

		BeforeAll(func() {
			socketsMap = sockets.NewSocketMap()
			socketsMap.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})
			processEvent(event1Payload, events.KSSLWrite)
			processEvent(event2Payload, events.KSSLRead)
			processEvent(event3Payload, events.KSSLRead)
			processEvent(event4Payload, events.KSSLWrite)
			processEvent(event5Payload, events.KSSLRead)
			processEvent(event6Payload, events.KSSLRead)
			processEvent(event7Payload, events.KSSLRead)
			processEvent(event8Payload, events.KSSLRead)
			processEvent(event9Payload, events.KSSLRead)
			processEvent(event10Payload, events.KSSLRead)
			processEvent(event11Payload, events.KSSLRead)
			processEvent(event12Payload, events.KSSLRead)
			processEvent(event13Payload, events.KSSLRead)
			processEvent(event14Payload, events.KSSLRead)
			processEvent(event15Payload, events.KSSLRead)
			processEvent(event16Payload, events.KSSLRead)
			processEvent(event17Payload, events.KSSLRead)
			processEvent(event18Payload, events.KSSLRead)
			processEvent(event19Payload, events.KSSLRead)
			processEvent(event20Payload, events.KSSLRead)

		})

		It("returns two flows", func() {
			Expect(len(flows)).To(Equal(2))

			for _, flow := range flows {
				Expect(flow.SourceAddr).To(Equal("172.17.0.2:1234"))
				Expect(flow.DestAddr).To(Equal("173.17.0.2:3306"))
				Expect(flow.L4Protocol).To(Equal("tcp"))
				Expect(flow.L7Protocol).To(Equal("mysql"))
				Expect(flow.PID).To(Equal(222))
				Expect(flow.FD).To(Equal(5))
			}

			query := flows[0].Request.(*sockets.MysqlQuery)

			Expect(query.Query).To(Equal("PREPARED STATEMENT"))
			Expect(len(query.Params)).To(Equal(0))
		})

		It("returns a response flow", func() {
			Expect(flows).To(HaveLen(2))
			resp := flows[1].Response.(*sockets.MysqlResponse)

			Expect(len(resp.Columns)).To(Equal(5))
			Expect(resp.Columns[0].Name).To(Equal("id"))
			Expect(resp.Columns[1].Name).To(Equal("name"))
			Expect(resp.Columns[2].Name).To(Equal("quantity"))
			Expect(resp.Columns[3].Name).To(Equal("price"))
			Expect(resp.Columns[4].Name).To(Equal("created_at"))

			Expect(len(resp.Rows)).To(Equal(1))
			Expect(resp.Rows[0][0]).To(Equal("1"))
			Expect(resp.Rows[0][1]).To(Equal("Widget"))
			Expect(resp.Rows[0][2]).To(Equal("5"))
			Expect(resp.Rows[0][3]).To(Equal("19.99"))
			Expect(resp.Rows[0][4]).To(Equal("2025-02-11 20:54:39.000000"))
		})
	})
})
