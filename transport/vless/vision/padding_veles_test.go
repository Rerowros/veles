package vision

import (
	"encoding/binary"
	"testing"

	"github.com/metacubex/mihomo/common/buf"

	"github.com/stretchr/testify/require"
)

// newPaddingTestBuffer returns a buffer holding contentLen bytes with room for
// the Vision header in front and rear free bytes behind.
func newPaddingTestBuffer(contentLen, rear int) *buf.Buffer {
	buffer := buf.NewSize(PaddingHeaderLen + contentLen + rear)
	buffer.Resize(PaddingHeaderLen, contentLen)
	return buffer
}

// applyTestPadding pads contentLen bytes once and returns the padding length
// written in the header, checking the frame layout.
func applyTestPadding(t *testing.T, contentLen, rear int, paddingTLS bool) int {
	buffer := newPaddingTestBuffer(contentLen, rear)
	defer buffer.Release()
	userUUID := make([]byte, 16)
	ApplyPadding(buffer, commandPaddingContinue, &userUUID, paddingTLS)
	header := buffer.Bytes()
	require.Equal(t, contentLen, int(binary.BigEndian.Uint16(header[17:19])))
	paddingLen := int(binary.BigEndian.Uint16(header[19:21]))
	require.Equal(t, PaddingHeaderLen+contentLen+paddingLen, buffer.Len())
	require.LessOrEqual(t, buffer.Len(), xrayBufSize, "frame must fit Xray's buffer")
	return paddingLen
}

// P30: records of 900 bytes and more get 0..255 random bytes, like Xray.
func TestVelesVisionPaddingLargeRecords(t *testing.T) {
	for _, paddingTLS := range []bool{true, false} {
		for _, contentLen := range []int{900, 1500, 4000, 7900} {
			var nonZero bool
			for i := 0; i < 200; i++ {
				paddingLen := applyTestPadding(t, contentLen, 1400, paddingTLS)
				require.Less(t, paddingLen, 256, "tls=%v len=%d", paddingTLS, contentLen)
				nonZero = nonZero || paddingLen > 0
			}
			require.True(t, nonZero, "tls=%v len=%d: no padding added", paddingTLS, contentLen)
		}
	}
}

// P30: near the 8192-byte limit the padding is clamped to 8192-21-contentLen.
func TestVelesVisionPaddingClampXrayBuffer(t *testing.T) {
	for _, contentLen := range []int{8000, 8100, 8170} {
		limit := xrayBufSize - PaddingHeaderLen - contentLen
		var atLimit bool
		for i := 0; i < 200; i++ {
			paddingLen := applyTestPadding(t, contentLen, 1400, true)
			require.LessOrEqual(t, paddingLen, limit)
			atLimit = atLimit || paddingLen == limit
		}
		if contentLen == 8170 {
			require.True(t, atLimit)
		}
	}
}

// P30: padding never runs past the buffer's capacity (Extend must not panic).
func TestVelesVisionPaddingClampFreeLen(t *testing.T) {
	for _, paddingTLS := range []bool{true, false} {
		for _, contentLen := range []int{0, 100, 1500} {
			for i := 0; i < 50; i++ {
				require.LessOrEqual(t, applyTestPadding(t, contentLen, 10, paddingTLS), 10)
			}
		}
	}
}

// Short records keep the old behaviour: long padding to 900..1399 with TLS,
// 0..255 without.
func TestVelesVisionPaddingShortRecords(t *testing.T) {
	for _, contentLen := range []int{0, 100, 899} {
		for i := 0; i < 100; i++ {
			total := contentLen + applyTestPadding(t, contentLen, 1400, true)
			require.GreaterOrEqual(t, total, 900)
			require.Less(t, total, 1400)
			require.Less(t, applyTestPadding(t, contentLen, 1400, false), 256)
		}
	}
}
