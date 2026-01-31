// Package bits provides some functions used for various purposes throught different packages.
package bits

import (
	"encoding/binary"
)

func Htons(num int) int {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(num))
	return int(binary.BigEndian.Uint32(b[:]))
}
