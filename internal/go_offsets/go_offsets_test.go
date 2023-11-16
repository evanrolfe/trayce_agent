package go_offsets

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const binPath = "/app/test/scripts/go_request"

// The offset values will change in newer Go versions, if it does just update the expected values here..
var _ = Describe("GoOffsets", func() {
	Context("GetSymbolOffset", Ordered, func() {
		var extOffset *GoExtendedOffset

		BeforeAll(func() {
			extOffset = GetSymbolOffset(binPath, "crypto/tls.(*Conn).Read")
		})

		It("returns the enter and exit offsets", func() {
			Expect(extOffset.Enter).To(Equal(uint64(2611840)))
			Expect(extOffset.Exits).To(Equal([]uint64{209, 290, 474, 656, 1100, 1197, 1392}))
		})
	})

	Context("GetStructMemberOffset", Ordered, func() {
		var offset uint64

		BeforeAll(func() {
			offset = GetStructMemberOffset(binPath, "internal/poll.FD", "Sysfd")
		})

		It("returns the correct offsets", func() {
			Expect(offset).To(Equal(uint64(16)))
		})
	})
})
