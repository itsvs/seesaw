package main

import (
	"fmt"
	"uuidcgo/uuid"
)

func main() {
	fmt.Println(uuid.CSetV4())
	fmt.Println(uuid.CReturnV4())
}
