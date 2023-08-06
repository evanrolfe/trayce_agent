package internal

// TODO: delete this. I think this is actually not needed anymore
type SocketEventsBuffer map[string][]*DataEvent

func NewSocketEventsBuffer() SocketEventsBuffer {
	buf := make(SocketEventsBuffer)
	return buf
}

func (buf SocketEventsBuffer) AddEvent(socket *SocketDesc, event *DataEvent) {
	events, exists := buf[event.Key()]
	if !exists {
		buf[event.Key()] = []*DataEvent{event}
		return
	}

	events = append(events, event)
}

func (buf SocketEventsBuffer) ClearEvents(socket *SocketDesc) []*DataEvent {
	events, exists := buf[socket.Key()]
	if !exists {
		return []*DataEvent{}
	}

	delete(buf, socket.Key())

	return events
}
