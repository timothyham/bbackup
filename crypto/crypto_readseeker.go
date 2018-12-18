package crypto

import (
	"errors"
	"io"

	"github.com/timothyham/bbackup/config"
)

type DecryptReadSeeker struct {
	enc         *Encryptor
	backingRs   io.ReadSeeker
	cipherBytes []byte
	plainBytes  []byte
	pendingSeek int64
	cursor      int64
	cursorChunk int64 // when cursorChunk == -1, chunk is not ready
	eof         bool
	tmpByte     []byte
}

func NewDecryptReadSeeker(key string, backingRs io.ReadSeeker) (io.ReadSeeker, error) {
	header := make([]byte, headerOffset)
	n, err := backingRs.Read(header)
	if err != nil || n != headerOffset {
		return nil, errors.New("could not read header")
	}
	if !(header[0] == 'b' && header[1] == 1) {
		return nil, errors.New("invalid header 1")
	}

	seeker := DecryptReadSeeker{}
	seeker.enc = NewDecryptor(key, "")
	seeker.enc.iv = header[2:headerOffset]

	seeker.backingRs = backingRs

	seeker.cipherBytes = make([]byte, ChunkSize+seeker.enc.Overhead)
	seeker.plainBytes = make([]byte, ChunkSize)
	seeker.tmpByte = make([]byte, 1)

	return &seeker, nil
}

func (seeker *DecryptReadSeeker) Read(b []byte) (int, error) {
	// check if I have to seek somewhere
	if seeker.pendingSeek > -1 { // seek to 0 is possible
		if debug {
			config.Logger.Printf("seeking to %v\n", seeker.pendingSeek)
		}
		// compute which chunk seek is in
		seekChunk := seeker.pendingSeek / int64(ChunkSize)
		if seekChunk != seeker.cursorChunk {
			// seeking to a different chunk. Invalidate the current chunk
			seeker.cursorChunk = -1
		}
		seeker.cursor = seeker.pendingSeek
		seeker.pendingSeek = -1
	}

	// check if cursor chunk needs to be decrypted
	if seeker.cursorChunk == -1 {
		seeker.cursorChunk = seeker.cursor / int64(ChunkSize)
		if debug {
			config.Logger.Printf("reading new chunk %v", seeker.cursorChunk)
		}
		cipherChunkOffset := seeker.cursorChunk * int64(ChunkSize+seeker.enc.Overhead)
		_, err := seeker.backingRs.Seek(int64(headerOffset)+cipherChunkOffset, 0)
		if err != nil {
			return 0, err
		}
		var n int
		n, err = seeker.backingRs.Read(seeker.cipherBytes)
		if err != nil {
			if err == io.EOF {
				seeker.eof = true
			}
			if err != io.EOF {
				return 0, err
			}
		}

		// there is an annoying behavior where the Read reaches EOF, but
		// doesn't report it until the next read, with 0 count. Since the
		// program always seeks to start of chunk, EOF can never be observed.
		// So force a read here to check if file reached EOF.
		m, err2 := seeker.backingRs.Read(seeker.tmpByte)
		if m == 0 && err2 != nil {
			seeker.eof = true
		}

		seeker.enc.ChunkIdx = seeker.cursorChunk
		seeker.plainBytes = seeker.plainBytes[:0]
		seeker.plainBytes, err = seeker.enc.DecryptChunk(seeker.plainBytes, seeker.cipherBytes[0:n])
		if err != nil {
			return 0, err
		}
	} else {
		if debug {
			config.Logger.Printf("reusing old chunk %v", seeker.cursorChunk)
		}
	}

	// at this point, seeker.plainBytes should have a chunk of plaintext
	offset := seeker.cursor % int64(ChunkSize)
	lenLeft := len(seeker.plainBytes) - int(offset)
	var n int
	if len(b) >= lenLeft { // finished the chunk
		n = copy(b[0:lenLeft], seeker.plainBytes[offset:])
		if n != lenLeft {
			return n, errors.New("inconsistency")
		}
		seeker.cursor += int64(n)
		seeker.cursorChunk = -1
	} else {
		n = copy(b[0:], seeker.plainBytes[offset:int(offset)+len(b)])
		seeker.cursor += int64(n)
	}

	var err error = nil
	if seeker.eof && seeker.cursorChunk == -1 {
		err = io.EOF
	}
	return n, err
}

/*
	Only 0 whence is supported
*/
func (seeker *DecryptReadSeeker) Seek(offset int64, whence int) (int64, error) {
	if offset < 0 {
		return 0, errors.New("cannot seek negative offset")
	}
	seeker.pendingSeek = offset
	seeker.eof = false

	return offset, nil
}
