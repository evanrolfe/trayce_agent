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

func (stream *Http2Stream) ProcessFrame(frame *Http2Frame) *Flow {
	// Only accept complete header or data frames, the rest are ignored
	acceptedTypes := []uint8{frameTypeData, frameTypeHeaders}
	if !frame.Complete() || !slices.Contains(acceptedTypes, frame.Type()) {
		return nil
	}

	if frame.Complete() && frame.Type() == frameTypeHeaders {
		return stream.processHeaderFrame(frame)

	} else if frame.Complete() && frame.Type() == frameTypeData {
		return stream.processDataFrame(frame)
	}

	return nil
}

func (stream *Http2Stream) processHeaderFrame(frame *Http2Frame) *Flow {
	if frame.IsRequest() {
		fmt.Println("[HTTP2Stream] processHeaderFrame (request)")
	} else {
		fmt.Println("[HTTP2Stream] processHeaderFrame (response)")
	}
	if frame.IsRequest() {
		httpReq := frame.ConvertToHTTPRequest()
		l7Protocol := "http2"
		if httpReq.IsGRPC() {
			l7Protocol = "grpc"
		}

		stream.activeFlow = NewFlowRequest(
			uuid.NewString(),
			"0.0.0.0",
			"127.0.0.1:80",
			"tcp",
			l7Protocol,
			123,
			5,
			httpReq,
		)

		activeUUID := stream.activeFlow.UUID
		stream.activeUuid = &activeUUID
		fmt.Println("[HTTP2Stream] activeUuid =", activeUUID)
	} else {
		if stream.activeUuid == nil {
			fmt.Println("ERROR: no active request UUID for this response")
			return nil
		}

		httpResp := frame.ConvertToHTTPResponse()
		l7Protocol := "http2"
		if httpResp.IsGRPC() {
			l7Protocol = "grpc"
		}

		// GRPC sends a header frame AFTER the data frames have been sent, this is the trailer frame and we ignore it
		// so if there is already an active flow then dont try and create a new one
		if stream.activeFlow == nil {
			stream.activeFlow = NewFlowResponse(
				*stream.activeUuid,
				"0.0.0.0",
				"127.0.0.1:80",
				"tcp",
				l7Protocol,
				123,
				5,
				httpResp,
			)
		}
	}

	// TODO: For requests with large headers split over multiple frames, this should add the header data to the activeFlow
	// just as it does in processDataFrame() and check the END_HEADERS flag to know when its complete

	// If there is no body in the request then send the flow back
	if frame.Flags().EndStream {
		flow := *stream.activeFlow
		stream.clearActiveFlow()
		if flow.Response != nil {
			stream.clearActiveUuid()
		}

		return &flow
	}

	return nil
}

func (stream *Http2Stream) processDataFrame(frame *Http2Frame) *Flow {
	if stream.activeFlow == nil {
		fmt.Println("ERROR: received http2 data frame but no active Flow")
		return nil
	}

	stream.activeFlow.AddPayload(frame.Payload())

	if frame.Flags().EndStream {
		// Send the flow back
		flow := *stream.activeFlow
		stream.clearActiveFlow()
		if flow.Response != nil {
			stream.clearActiveUuid()
		}

		return &flow
	}

	return nil
}

func (stream *Http2Stream) clearActiveFlow() {
	stream.activeFlow = nil
}

func (stream *Http2Stream) clearActiveUuid() {
	stream.activeUuid = nil
}
