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
			Expect(extOffset.Enter).To(Equal(uint64(2934272)))
			Expect(extOffset.Exits).To(Equal([]uint64{2934454, 2934530, 2934707, 2934869, 2935362, 2935429, 2935605}))
		})
	})

	Context("GetStructMemberOffset", Ordered, func() {
		var offset uint64

		BeforeAll(func() {
			offset, _ = GetStructMemberOffset(binPath, "internal/poll.FD", "Sysfd")
		})

		It("returns the correct offsets", func() {
			Expect(offset).To(Equal(uint64(16)))
		})
	})
})
