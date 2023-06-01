package proxy

import (
	"log"
	"net"
)

func StartProxy() {
	listener, err := net.Listen("tcp", ":8888") // Replace with the desired proxy listen address
	if err != nil {
		log.Fatalf("Failed to start listener: %s", err)
	}
	log.Println("TCP Proxy started on :8888")

	go handleConnections(listener)
}

func handleConnections(listener net.Listener) {
	for {
		inBoundConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept client connection: %s", err)
			continue
		}

		twoWayConn := NewTCPFlow(inBoundConn)
		defer twoWayConn.CloseConns()

		twoWayConn.ConnectOutbound()
		go twoWayConn.Stream()
		// go handleConnection(inBoundConn)
	}
}
