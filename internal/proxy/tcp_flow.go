package proxy

import (
	"io"
	"log"
	"net"
)

type TCPFlow struct {
	// inBoundConn is from client to proxy
	inBoundConn net.Conn
	// outBoundConn is from proxy to remote
	outBoundConn net.Conn
}

func NewTCPFlow(inBoundConn net.Conn) *TCPFlow {
	flow := &TCPFlow{
		inBoundConn: inBoundConn,
	}

	log.Printf("RemoteAddr: %v LocalAddr: %v", inBoundConn.RemoteAddr().String(), inBoundConn.LocalAddr().String())

	return flow
}

func (flow *TCPFlow) ConnectOutbound() {
	// Connect to the intended destination
	outBoundConn, err := net.Dial("tcp", "172.67.170.141:80") // Replace with the desired destination address
	if err != nil {
		log.Printf("Failed to connect to destination: %s", err)
		return
	}

	flow.outBoundConn = outBoundConn
}

func (flow *TCPFlow) CloseConns() {
	flow.inBoundConn.Close()
	flow.outBoundConn.Close()
}

func (flow *TCPFlow) Stream() {
	inBuffer := make([]byte, 1024)
	outBuffer := make([]byte, 1024)

	// Copy data from inboundConn to outboundConn
	go func() {
		for {
			n, err := flow.inBoundConn.Read(inBuffer)
			if err != nil {
				if err != io.EOF {
					log.Printf("Error reading data from inBoundConn: %s", err)
				}
				break
			}

			data := inBuffer[:n]
			log.Printf("Received data from inBoundConn: %s", string(data))

			// Forward the data to outBoundConn
			_, err = flow.outBoundConn.Write(data)
			if err != nil {
				log.Printf("Error writing data to outBoundConn: %s", err)
				break
			}
		}
	}()

	// Copy data from outboundConn to inboundConn
	for {
		n, err := flow.outBoundConn.Read(outBuffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading data from outBoundConn: %s", err)
			}
			break
		}

		data := outBuffer[:n]
		log.Printf("Received data from outBoundConn: %s", string(data))

		// Forward the data to inBoundConn
		_, err = flow.inBoundConn.Write(data)
		if err != nil {
			log.Printf("Error writing data to inBoundConn: %s", err)
			break
		}
	}
}

// inBuffer := []byte{}
// outBuffer := make([]byte, 1024)
// // outBuffer := bytes.NewBuffer([]byte{})
// // Copy data from inboundConn to outboundConn
// go func() {
// 	for {
// 		buf := make([]byte, 1024)
// 		n, err := inBoundConn.Read(buf)
// 		if err != nil {
// 			if err != io.EOF {
// 				log.Printf("Error reading data from inBoundConn: %s", err)
// 			}
// 			break
// 		}

// 		data := buf[:n]
// 		inBuffer = append(inBuffer, data...)

// 		log.Printf("Received data from inBoundConn: %s", string(data))

// 		if bytes.Contains(inBuffer, []byte("\r\n")) {
// 			// Forward the data to outBoundConn
// 			_, err = outBoundConn.Write(inBuffer)
// 			if err != nil {
// 				log.Printf("Error writing data to outBoundConn: %s", err)
// 				break
// 			}
// 		}
// 	}
// }()
