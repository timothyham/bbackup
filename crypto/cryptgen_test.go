package crypto

import (
	"io/ioutil"
	"math/rand"
	"os"
	"testing"
)

// generate one meg text file with internal markers start/end
func testGenerate1MiBText(t *testing.T) {
	run := false
	if run == false {
		return
	}

	total := 1024 * 1024   // 1048576 bytes == 1 MiB
	chunkSize := total / 4 // 256KiB

	b := make([]byte, total)
	r := rand.New(rand.NewSource(1))
	// lower case [a-z] is 97-122. Space is 32
	var ch int
	for j := 0; j < 4; j++ {
		b[chunkSize*j] = 's'
		b[chunkSize*j+1] = 't'
		b[chunkSize*j+2] = 'a'
		b[chunkSize*j+3] = 'r'
		b[chunkSize*j+4] = 't'
		for i := 5; i < chunkSize-3; i++ {
			if i%80 == 0 {
				b[chunkSize*j+i] = 10 // newline
				continue
			}
			n := r.Intn(27)
			if n == 0 {
				ch = 32
			} else {
				ch = n + 96
			}
			b[chunkSize*j+i] = byte(ch)
		}
		b[chunkSize*j+chunkSize-3] = 'e'
		b[chunkSize*j+chunkSize-2] = 'n'
		b[chunkSize*j+chunkSize-1] = 'd'
	}
	ioutil.WriteFile("testdata/onemeg.txt", b, os.ModePerm)
}
