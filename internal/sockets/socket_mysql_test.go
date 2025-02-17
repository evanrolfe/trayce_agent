package sockets_test

import (
	"github.com/evanrolfe/trayce_agent/internal/events"
	"github.com/evanrolfe/trayce_agent/internal/sockets"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("SocketMysql", func() {
	Context("Receiving a `SELECT * FROM schema_migrations` query and response", Ordered, func() {
		flows := []*sockets.Flow{}

		// Request payloads
		event1Payload, _ := hexDumpToBytes(mysqlQueryMigrations1)
		event2Payload, _ := hexDumpToBytes(mysqlQueryMigrations2)
		event3Payload, _ := hexDumpToBytes(mysqlQueryMigrations3)
		event4Payload, _ := hexDumpToBytes(mysqlQueryMigrations4)
		event5Payload, _ := hexDumpToBytes(mysqlQueryMigrations5)
		event6Payload, _ := hexDumpToBytes(mysqlQueryMigrations6)
		event7Payload, _ := hexDumpToBytes(mysqlQueryMigrations7)
		event8Payload, _ := hexDumpToBytes(mysqlQueryMigrations8)
		event9Payload, _ := hexDumpToBytes(mysqlQueryMigrations9)

		BeforeAll(func() {
			socket := sockets.SocketMysql{
				Common: sockets.SocketCommon{
					SourceAddr: "172.17.0.2:1234",
					DestAddr:   "173.17.0.2:3306",
					PID:        123,
					TID:        123,
					FD:         5,
					SSL:        false,
				},
			}
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})

			processEvent := func(payload []byte, source uint64) {
				socket.ProcessDataEvent(&events.DataEvent{
					PID:        1232,
					TID:        1232,
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

			processEvent(event1Payload, events.KSSLWrite)
			processEvent(event2Payload, events.KSSLRead)
			processEvent(event3Payload, events.KSSLRead)
			processEvent(event4Payload, events.KSSLRead)
			processEvent(event5Payload, events.KSSLRead)
			processEvent(event6Payload, events.KSSLRead)
			processEvent(event7Payload, events.KSSLRead)
			processEvent(event8Payload, events.KSSLRead)
			processEvent(event9Payload, events.KSSLRead)

		})

		It("returns a request flow", func() {
			Expect(len(flows)).To(Equal(2))

			for _, flow := range flows {
				Expect(flow.SourceAddr).To(Equal("172.17.0.2:1234"))
				Expect(flow.DestAddr).To(Equal("173.17.0.2:3306"))
				Expect(flow.L4Protocol).To(Equal("tcp"))
				Expect(flow.L7Protocol).To(Equal("mysql"))
				Expect(flow.PID).To(Equal(123))
				Expect(flow.FD).To(Equal(5))
			}

			query := flows[0].Request.(*sockets.MysqlQuery)

			Expect(query.Query).To(Equal(`SELECT table_name FROM information_schema.tables WHERE table_schema = database() AND table_name = 'schema_migrations' AND table_name IN (SELECT table_name FROM information_schema.tables WHERE table_schema = database()) AND table_type = 'BASE TABLE'`))
			Expect(len(query.Params)).To(Equal(0))
		})

		It("returns a response flow", func() {
			Expect(flows).To(HaveLen(2))
			resp := flows[1].Response.(*sockets.MysqlResponse)

			Expect(len(resp.Columns)).To(Equal(1))
			Expect(resp.Columns[0].Name).To(Equal("TABLE_NAME"))

			Expect(len(resp.Rows)).To(Equal(1))
			Expect(len(resp.Rows[0])).To(Equal(1))
			Expect(resp.Rows[0][0]).To(Equal("schema_migrations"))
		})
	})

	// It("returns a request flow", func() {
	// 	data := []byte{0x01, 0x00, 0x00, 0x02, 0x01}
	// 	messages := sockets.ExtractMySQLMessages(data)

	// 	Expect(len(messages)).To(Equal(1))

	// 	Expect(len(messages[0].Payload)).To(Equal(1))
	// 	Expect(messages[0].SequenceNum).To(Equal(2))
	// })

	Context("Receiving an UPDATE query transaction", Ordered, func() {
		flows := []*sockets.Flow{}

		// Request payloads
		event1Payload, _ := hexDumpToBytes(mysqlUpdateQuery1)
		event2Payload, _ := hexDumpToBytes(mysqlUpdateQuery1)
		event3Payload, _ := hexDumpToBytes(mysqlUpdateQuery3)
		event4Payload, _ := hexDumpToBytes(mysqlUpdateQuery4)
		event5Payload, _ := hexDumpToBytes(mysqlUpdateQuery5)
		event6Payload, _ := hexDumpToBytes(mysqlUpdateQuery6)
		event7Payload, _ := hexDumpToBytes(mysqlUpdateQuery7)

		BeforeAll(func() {
			socketUnknown := sockets.NewSocketUnknownFromData(&events.DataEvent{
				PID:        123,
				TID:        123,
				FD:         5,
				DataType:   7, // go_tls_write
				Data:       [4096]byte{0},
				DataLen:    0,
				SourceHost: 33558956,
				SourcePort: 1234,
				DestHost:   16777343,
				DestPort:   3306,
			})
			socket := sockets.NewSocketMysqlFromUnknown(&socketUnknown)
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})

			processEvent := func(payload []byte, source uint64) {
				socket.ProcessDataEvent(&events.DataEvent{
					PID:        1232,
					TID:        1232,
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

			processEvent(event1Payload, events.KSSLWrite)
			processEvent(event2Payload, events.KSSLWrite)
			processEvent(event3Payload, events.KSSLWrite)
			processEvent(event4Payload, events.KSSLWrite)
			processEvent(event5Payload, events.KSSLWrite)
			processEvent(event6Payload, events.KSSLWrite)
			processEvent(event7Payload, events.KSSLWrite)
		})

		It("returns a request flow", func() {
			Expect(len(flows)).To(Equal(3))

			for _, flow := range flows {
				Expect(flow.SourceAddr).To(Equal("172.17.0.2:1234"))
				Expect(flow.DestAddr).To(Equal("127.0.0.1:3306"))
				Expect(flow.L4Protocol).To(Equal("tcp"))
				Expect(flow.L7Protocol).To(Equal("mysql"))
				Expect(flow.PID).To(Equal(123))
				Expect(flow.FD).To(Equal(5))
			}

			query0 := flows[0].Request.(*sockets.MysqlQuery)
			Expect(query0.Query).To(Equal("BEGIN"))
			Expect(len(query0.Params)).To(Equal(0))

			query1 := flows[1].Request.(*sockets.MysqlQuery)
			Expect(query1.Query).To(Equal("UPDATE `things` SET `things`.`quantity` = ? WHERE `things`.`id` = ?"))
			Expect(len(query1.Params)).To(Equal(0))

			query2 := flows[2].Request.(*sockets.MysqlQuery)
			Expect(query2.Query).To(Equal("COMMIT"))
			Expect(len(query2.Params)).To(Equal(0))
		})
	})
})
