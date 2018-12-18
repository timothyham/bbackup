package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

var ChunkSize = int64(1024 * 256) // 256KiB
var debug = false
var version = []byte{'b', 1}
var headerOffset = 26 // 2 for version + 24 iv

type Encryptor struct {
	aead     cipher.AEAD
	key      []byte // 32 bytes or 256 bits
	iv       []byte // 24 bytes or 192 bits
	nonce    []byte // 24 bytes or 192 bits
	ChunkIdx int64  // chuckCount used to derive nonce
	Overhead int64  // 16
}

type Hash struct {
	InSHA1    string
	InSHA256  string
	OutSHA1   string
	OutSHA256 string
}

func EqualHash(a, b Hash) bool {
	if a.InSHA1 != b.InSHA1 {
		return false
	}
	if a.InSHA256 != b.InSHA256 {
		return false
	}
	if a.OutSHA1 != b.OutSHA1 {
		return false
	}
	if a.OutSHA256 != b.OutSHA256 {
		return false
	}
	return true
}

// Init sets up the internal oncryptor using current key and iv.
func (e *Encryptor) Init() {
	aead, err := chacha20poly1305.NewX(e.key)
	if err != nil {
		panic("could not creat aead:" + err.Error())
	}
	e.aead = aead
	e.Overhead = int64(aead.Overhead())
	e.ChunkIdx = 0
}

// NewEncryptor generates a new random key, iv
func NewEncryptor() *Encryptor {
	e := Encryptor{}
	newkey := make([]byte, 256/8)
	_, err := rand.Read(newkey)
	if err != nil {
		panic("Could not generate random key")
	}
	e.key = newkey

	newiv := make([]byte, 192/8)
	_, err = rand.Read(newiv)
	if err != nil {
		panic("Could not generate iv")
	}
	e.iv = newiv

	e.Init()

	return &e
}

func NewDecryptor(key, iv string) *Encryptor {
	e := Encryptor{}
	var err error
	e.key, err = hex.DecodeString(key)
	if err != nil {
		panic(err)
	}
	e.iv, err = hex.DecodeString(iv)
	if err != nil {
		panic(err)
	}
	e.Init()

	return &e
}
func (e *Encryptor) GetKey() string {
	return fmt.Sprintf("%x", e.key)
}

func (e *Encryptor) GetIv() string {
	return fmt.Sprintf("%x", e.iv)
}

func (e *Encryptor) SetKey(key string) {
	k, err := hex.DecodeString(key)
	if err == nil {
		e.key = k
	}
}

func (e *Encryptor) SetIv(iv string) {
	i, err := hex.DecodeString(iv)
	if err == nil {
		e.iv = i
	}
}

// Read plain/cipher text from in io.Reader and writes plain/cipher
// text to out io.Writer. If encrypt is true, then in is the plaintext.
func (e *Encryptor) Encrypt(out io.Writer, in io.Reader, encrypt bool) (Hash, error) {
	hash := Hash{}

	inSha256 := sha256.New()
	inSha1 := sha1.New()
	outSha256 := sha256.New()
	outSha1 := sha1.New()

	e.ChunkIdx = 0
	bufSize := 1024 * 64

	var scratch []byte
	var inChunkSize int64
	var outChunkSize int64
	if encrypt {
		inChunkSize = ChunkSize
		outChunkSize = ChunkSize + e.Overhead
		n, err := out.Write(version)
		outSha1.Write(version)
		outSha256.Write(version)
		if err != nil || n != 2 {
			return hash, errors.New("could not write header part 1")
		}
		n, err = out.Write(e.iv)
		outSha1.Write(e.iv)
		outSha256.Write(e.iv)
		if err != nil || n != 24 {
			return hash, errors.New("could not write header part 2")
		}
	} else {
		inChunkSize = ChunkSize + e.Overhead
		outChunkSize = ChunkSize

		header := make([]byte, headerOffset)
		n, err := in.Read(header)
		if err != nil || n != headerOffset {
			return hash, errors.New("could not read header")
		}
		if !(header[0] == 'b' && header[1] == 1) {
			return hash, errors.New("unrecognized header")
		}
		e.iv = header[2:headerOffset]
		inSha1.Write(header)
		inSha256.Write(header)
	}
	inBytes := make([]byte, inChunkSize)
	outBytes := make([]byte, outChunkSize)
	inCount := int64(0)
	scratch = make([]byte, bufSize)

	for {
		n, err := in.Read(scratch)
		n64 := int64(n)
		if inCount+n64 < inChunkSize { // still filing chunk
			o := copy(inBytes[inCount:], scratch[0:n])
			inSha1.Write(scratch[0:n])
			inSha256.Write(scratch[0:n])
			if debug {
				fmt.Printf("filling: incount, n: %d %d\n", inCount, n)
			}
			if o != n {
				return hash, errors.New(fmt.Sprintf("1: Expected %d, but copied %d", n, o))
			}
			inCount += n64
		} else { // finish chunk and start new chunk
			// fill chunk
			if debug {
				fmt.Printf("else: incount, n: %d %d\n", inCount, n)
			}
			lenPartial := inChunkSize - inCount
			remaining := n64 - lenPartial
			if debug {
				fmt.Printf("lenPartial, remaining: %d %d\n", lenPartial, remaining)
			}
			o := copy(inBytes[inCount:], scratch[0:lenPartial])
			o64 := int64(o)
			inSha1.Write(scratch[0:lenPartial])
			inSha256.Write(scratch[0:lenPartial])
			if o64 != lenPartial {
				return hash, errors.New(fmt.Sprintf("2: Expected %d, but copied %d", lenPartial, o))
			}
			inCount += o64
			outBytes = outBytes[:0]
			// fill outbuf
			if encrypt {
				outBytes = e.aead.Seal(outBytes, e.currentNonce(), inBytes[0:inCount], nil)
			} else {
				outBytes, err = e.aead.Open(outBytes, e.currentNonce(), inBytes[0:inCount], nil)
				if err != nil {
					return hash, err
				}
			}
			w, err := out.Write(outBytes)
			if err != nil {
				return hash, err
			}
			outSha1.Write(outBytes)
			outSha256.Write(outBytes)
			if debug {
				fmt.Printf("wrote %d bytes\n", w)
			}
			if w != len(outBytes) {
				return hash, errors.New(fmt.Sprintf("Expected to write %d, but actually wrote %d", len(outBytes), w))
			}

			// continue
			e.ChunkIdx += 1
			inCount = 0
			// and fill with remaining partial
			if lenPartial > 0 {
				o = copy(inBytes[inCount:], scratch[lenPartial:n])
				o64 := int64(o)
				inSha1.Write(scratch[lenPartial:n])
				inSha256.Write(scratch[lenPartial:n])
				if o64 != remaining {
					return hash, errors.New(fmt.Sprintf("3: Expected %d, but copied %d", remaining, o))
				}
				inCount += o64
			}
		}
		if err != nil {
			if err == io.EOF {
				if debug {
					fmt.Printf("EOF\n")
				}
				break
			}
			return hash, err
		}
	}
	// write the rest
	if inCount > 0 {
		var err error
		outBytes = outBytes[:0]
		if encrypt {
			outBytes = e.aead.Seal(outBytes, e.currentNonce(), inBytes[0:inCount], nil)
		} else {
			outBytes, err = e.aead.Open(outBytes, e.currentNonce(), inBytes[0:inCount], nil)
			if err != nil {
				return hash, err
			}
		}
		if len(outBytes) > 0 {
			w, err := out.Write(outBytes)
			if debug {
				fmt.Printf("wrote remaining %d bytes\n", w)
			}
			outSha1.Write(outBytes)
			outSha256.Write(outBytes)
			if err != nil {
				return hash, err
			}
			if w != len(outBytes) {
				return hash, errors.New(fmt.Sprintf("Expected to write %d, but actually wrote %d", len(outBytes), w))
			}
		}
	}

	hash.InSHA1 = fmt.Sprintf("%x", inSha1.Sum(nil))
	hash.InSHA256 = fmt.Sprintf("%x", inSha256.Sum(nil))
	hash.OutSHA1 = fmt.Sprintf("%x", outSha1.Sum(nil))
	hash.OutSHA256 = fmt.Sprintf("%x", outSha256.Sum(nil))
	return hash, nil
}

// compute 192 bit (24 byte) nonce from iv and ChunkIdx
func (e *Encryptor) currentNonce() []byte {
	if e.nonce == nil {
		e.nonce = make([]byte, chacha20poly1305.NonceSizeX)
		copy(e.nonce, e.iv)
	}

	num := binary.LittleEndian.Uint64(e.iv[16:])
	num += uint64(e.ChunkIdx)
	if debug {
		fmt.Printf("new nonce with ChunkIdx %d\n", num)
	}
	binary.LittleEndian.PutUint64(e.nonce[16:], num)
	return e.nonce
}

func (e *Encryptor) DecryptChunk(plainBytes, cipherBytes []byte) ([]byte, error) {
	outBytes, err := e.aead.Open(plainBytes, e.currentNonce(), cipherBytes, nil)
	return outBytes, err
}

// ReadWrite returns the number of bytes processed, the write sha256, and read sha256, and error
func (e *Encryptor) ReadWrite(w io.Writer, r io.Reader) (int, string, string, error) {
	bufsize := 1024 * 128 // 128KB
	in := make([]byte, bufsize)
	out := make([]byte, bufsize)

	insha256 := sha256.New()
	outsha256 := sha256.New()

	stop := false
	sumn := 0
	for !stop {
		n, err := r.Read(in)
		if n < bufsize {
			if err == io.EOF {
				stop = true
			} else if err != nil {
				return sumn, "", "", err
			}
		}
		insha256.Write(in[:n])
		outsha256.Write(out[:n])
		m, err := w.Write(out[:n])
		if m != n {
			return sumn, "", "", errors.New("Write error")
		}
		if stop {
			return sumn, BytesToString(outsha256.Sum(nil)), BytesToString(insha256.Sum(nil)), err
		}

		sumn += n
	}

	return sumn, BytesToString(outsha256.Sum(nil)), BytesToString(insha256.Sum(nil)), nil
}

func BytesToString(b []byte) string {
	return fmt.Sprintf("%x", b)
}

// NewEncname generates a random 200 bit number and returns the base32 string
func NewEncname() string {
	newkey := make([]byte, 200/8)
	_, _ = rand.Read(newkey)
	name := base32.StdEncoding.EncodeToString(newkey)
	return name
}
