package mongosqlauth

import (
	"crypto/md5"
	"fmt"
	"io"
)

func mongoPasswordDigest(username, password string) string {
	h := md5.New()
	io.WriteString(h, username)
	io.WriteString(h, ":mongo:")
	io.WriteString(h, password)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func bytesToUint32(b []byte) uint32 {
	return (uint32(b[0])) |
		(uint32(b[1]) << 8) |
		(uint32(b[2]) << 16) |
		(uint32(b[3]) << 24)
}

func uint32ToBytes(n uint32) []byte {
	return []byte{
		byte(n),
		byte(n >> 8),
		byte(n >> 16),
		byte(n >> 24),
	}
}
