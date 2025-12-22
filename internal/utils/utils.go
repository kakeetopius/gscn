// Package utils provides some functions used for various purposes throught different packages.
package utils

import (
	"encoding/binary"
	"fmt"
	"strings"
)

func Htons(num int) int {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(num))
	return int(binary.BigEndian.Uint32(b[:]))
}

func GetErrString(err error) string {
	errStr := fmt.Sprintf("%v", err)
	errStrings := strings.Split(errStr, ":")
	errStr = errStrings[len(errStrings)-1]

	return errStr
}
