package sockets

import (
	"fmt"
	"slices"

	"github.com/google/uuid"
)

type Http2Stream struct {
	activeFlow *Flow
	// activeUuid is used to keep track of the request uuid so that when a response is processed, its flow can have the same uuid as the request
	activeUuid *string
}

func NewHttp2Stream() *Http2Stream {
	return &Http2Stream{}
}

func (strm *Http2Stream) ProcessFrame(frame *Http2Frame) *Flow {
	// Only accept complete header or data frames, the rest are ignored
	acceptedTypes := []uint8{frameTypeData, frameTypeHeaders}
	if !frame.Complete() || !slices.Contains(acceptedTypes, frame.Type()) {
		return nil
	}

	if frame.Complete() && frame.Type() == frameTypeHeaders {
		return strm.processHeaderFrame(frame)

	} else if frame.Complete() && frame.Type() == frameTypeData {
		return strm.processDataFrame(frame)
	}

	return nil
}

func (strm *Http2Stream) processHeaderFrame(frame *Http2Frame) *Flow {
	if frame.IsRequest() {
		fmt.Println("[HTTP2Stream] processHeaderFrame (request)")
	} else {
		fmt.Println("[HTTP2Stream] processHeaderFrame (response)")
	}
	if frame.IsRequest() {
		req, err := frame.ConvertToFlowRequest()
		if err != nil {
			fmt.Println("ERROR ConvertToFlowRequest():", err)
			return nil
		}

		var l7Protocol string
		switch req.(type) {
		case *GRPCRequest:
			l7Protocol = "grpc"
		case *HTTPRequest:
			l7Protocol = "http2"
		default:
			l7Protocol = "http2"
		}

		strm.activeFlow = NewFlowRequest(
			uuid.NewString(),
			"0.0.0.0",
			"127.0.0.1:80",
			"tcp",
			l7Protocol,
			123,
			5,
			req,
		)

		activeUUID := strm.activeFlow.UUID
		strm.activeUuid = &activeUUID
		fmt.Println("[HTTP2Stream] activeUuid =", activeUUID)
	} else {
		if strm.activeUuid == nil {
			fmt.Println("ERROR: no active request UUID for this response")
			return nil
		}

		resp, err := frame.ConvertToFlowResponse()
		if err != nil {
			fmt.Println("ERROR ConvertToFlowResponse():", err)
		}

		// GRPC sends a header frame AFTER the data frames have been sent, this is the trailer frame and we ignore it
		// so if there is already an active flow then dont try and create a new one
		if strm.activeFlow == nil && resp != nil {
			var l7Protocol string
			switch resp.(type) {
			case *GRPCResponse:
				l7Protocol = "grpc"
			case *HTTPResponse:
				l7Protocol = "http2"
			default:
				l7Protocol = "http2"
			}

			strm.activeFlow = NewFlowResponse(
				*strm.activeUuid,
				"0.0.0.0",
				"127.0.0.1:80",
				"tcp",
				l7Protocol,
				123,
				5,
				resp,
			)
		}
	}

	// TODO: For requests with large headers split over multiple frames, this should add the header data to the activeFlow
	// just as it does in processDataFrame() and check the END_HEADERS flag to know when its complete

	// If there is no body in the request then send the flow back
	if frame.Flags().EndStream {
		flow := *strm.activeFlow
		strm.clearActiveFlow()
		if flow.Response != nil {
			strm.clearActiveUuid()
		}

		return &flow
	}

	return nil
}

func (strm *Http2Stream) processDataFrame(frame *Http2Frame) *Flow {
	if strm.activeFlow == nil {
		fmt.Println("ERROR: received http2 data frame but no active Flow")
		return nil
	}

	strm.activeFlow.AddPayload(frame.Payload())

	if frame.Flags().EndStream {
		// Send the flow back
		flow := *strm.activeFlow
		strm.clearActiveFlow()
		if flow.Response != nil {
			strm.clearActiveUuid()
		}

		return &flow
	}

	return nil
}

func (strm *Http2Stream) clearActiveFlow() {
	strm.activeFlow = nil
}

func (strm *Http2Stream) clearActiveUuid() {
	strm.activeUuid = nil
}
