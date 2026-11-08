package main

/*
#include <stdlib.h>
*/
import "C"

// The JNI entry points live in jni_android.c and call these.

//export wgStart
func wgStart(config *C.char, port C.int) C.int {
	p, err := start(C.GoString(config), int(port))
	setLastError(err)
	if err != nil {
		return -1
	}
	return C.int(p)
}

//export wgStop
func wgStop() {
	stop()
}

// wgLastError returns a malloc'd copy of the last error; the caller frees it.
//
//export wgLastError
func wgLastError() *C.char {
	mu.Lock()
	defer mu.Unlock()
	return C.CString(lastError)
}

func main() {}
