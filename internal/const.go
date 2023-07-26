package internal

type AttachType int64

const (
	ProbeEntry AttachType = iota
	ProbeRet
)

const MaxDataSize = 1024 * 4
const SaDataLen = 14

const (
	Ssl2Version   = 0x0002
	Ssl3Version   = 0x0300
	Tls1Version   = 0x0301
	Tls11Version  = 0x0302
	Tls12Version  = 0x0303
	Tls13Version  = 0x0304
	Dtls1Version  = 0xFEFF
	Dtls12Version = 0xFEFD
)

type TlsVersion struct {
	Version int32
}
