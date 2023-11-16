package go_offsets

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestGoOffsets(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "GoOffsets Suite")
}
