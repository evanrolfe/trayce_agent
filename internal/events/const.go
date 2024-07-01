package events

type AttachType int64

const (
	ProbeEntry AttachType = iota
	ProbeRet
)

const MaxDataSize = 1024 * 4
