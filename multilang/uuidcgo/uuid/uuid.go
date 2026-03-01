package uuid

/*
#include "uuid.h"
#include <stdlib.h>
*/
import "C"

func CSetV4() string {
	uuidStr := C.malloc(37)
	defer C.free(uuidStr)

	C.generate_set_uuid4((*C.char)(uuidStr))
	return C.GoString((*C.char)(uuidStr))
}

func CReturnV4() string {
	uuidStr := C.malloc(37)
	defer C.free(uuidStr)

	result := C.generate_return_uuid4((*C.char)(uuidStr))
	return C.GoString(result)
}
