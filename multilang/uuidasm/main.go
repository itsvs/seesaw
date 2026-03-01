package main

import (
	"fmt"
	"strings"
)

const HEX = "0123456789abcdef"

func uuidv4(out *[16]byte)

func ASMV4() string {
	var buf [16]byte
	uuidv4(&buf)

	var b strings.Builder
	b.Grow(36)

	for i, v := range buf {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			b.WriteByte('-')
		}
		b.WriteByte(HEX[v>>4])
		b.WriteByte(HEX[v&0x0F])
	}
	return b.String()
}

func main() {
	fmt.Println(ASMV4())
}
