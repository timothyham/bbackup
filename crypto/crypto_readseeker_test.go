package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"os"
	"testing"
)

// Used to generate encrypted file
func testGenerate(t *testing.T) {
	plaintext, err := os.Open("testdata/big_buck_bunny.mp4")
	defer plaintext.Close()
	if err != nil {
		t.Error("Could not open file")
	}

	ciphertext, err := os.Create("testdata/big_buck_bunny.enc")
	if err != nil {
		t.Error("Could not open output file")
	}

	encryptor := NewEncryptor()
	encryptor.SetKey("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
	encryptor.SetIv("000102030405060708090a0b0c0d0e0f0001020304050607")
	encryptor.Init()

	hash, err := encryptor.Encrypt(ciphertext, plaintext, true)
	fmt.Printf("insha1 %s\n", hash.InSHA1)
	fmt.Printf("insha256 %s\n", hash.InSHA256)
	fmt.Printf("outsha1 %s\n", hash.OutSHA1)
	fmt.Printf("outsha256 %s\n", hash.OutSHA256)
}

func TestReadSeeker(t *testing.T) {
	plainfile := "testdata/big_buck_bunny.mp4"
	plainf, err := os.Open(plainfile)
	defer plainf.Close()
	if err != nil {
		t.Fatal("Couldn't open test file")
	}

	encfile := "testdata/big_buck_bunny.enc"

	keyHex := "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"
	key, _ := hex.DecodeString(keyHex)
	keyB64 := base64.RawURLEncoding.EncodeToString(key)
	f, err := os.Open(encfile)
	defer f.Close()
	if err != nil {
		t.Fatal("Couldn't open test file")
	}

	pInfo, err := plainf.Stat()
	if err != nil {
		t.Fatalf("%v", err)
	}
	lenFile := pInfo.Size()
	dec, err := NewDecryptReadSeeker(keyB64, lenFile, f)
	if err != nil {
		t.Fatalf("%v", err)
	}
	pbytes := make([]byte, 16)
	decbytes := make([]byte, 16)

	r := rand.New(rand.NewSource(1))

	for i := 0; i < 1000; i++ {
		newOffset := int64(r.Intn(int(lenFile)))
		_, err := plainf.Seek(newOffset, 0)
		if err != nil {
			t.Errorf("%v", err)
		}
		_, err = dec.Seek(newOffset, 0)
		if err != nil {
			t.Errorf("%v", err)
		}
		_, err = dec.Read(decbytes)
		if err != nil {
			t.Errorf("%v", err)
		}
		_, err = plainf.Read(pbytes)
		if err != nil {
			t.Errorf("%v", err)
		}

		if !bytes.Equal(decbytes, pbytes) {
			t.Errorf("%d: Bytes differ at offset %v\n db: %x\n pb: %x\n", i, newOffset, pbytes, decbytes)

			break
		}
	}

	// read the whole file
	decbytes = make([]byte, 1024*8-1) // weird size uncovers bugs
	pbytes = make([]byte, 1024*8-1)
	_, err = plainf.Seek(0, 0)
	_, err = dec.Seek(0, 0)

	ptext := make([]byte, 0)
	dectext := make([]byte, 0)
	counter := 0
	for {
		n, err := plainf.Read(pbytes)
		ptext = append(ptext, pbytes[:n]...)
		if err != nil {
			if err != io.EOF {
				t.Errorf("unexpected error %v", err)
			}
			break
		}
		counter++
	}

	counter = 0
	for {
		n, err := dec.Read(decbytes)
		dectext = append(dectext, decbytes[:n]...)
		if err != nil {
			if err != io.EOF {
				t.Errorf("unexpected error %v", err)
			}
			break
		}
		counter++
	}

	if len(dectext) != len(ptext) {
		t.Errorf("read lengths are different %v %v", len(dectext), len(ptext))
	}
	if len(dectext) != 5510872 {
		t.Errorf("unexpected size %d", len(dectext))
	}
	for i, b := range ptext {
		if dectext[i] != b {
			t.Errorf("unexpected byte %v %v", b, dectext[i])
			break
		}
	}
}

func TestReadWhole(t *testing.T) {
	plainfile := "testdata/big_buck_bunny.mp4"
	plainf, err := os.Open(plainfile)
	defer plainf.Close()
	if err != nil {
		t.Fatal("Couldn't open test file")
	}
	st, err := plainf.Stat()
	if err != nil {
		t.Fatal("could not get stat for plainfile")
	}
	encfile := "testdata/big_buck_bunny.enc"

	keyHex := "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"
	key, _ := hex.DecodeString(keyHex)
	keyB64 := base64.RawURLEncoding.EncodeToString(key)
	fmt.Printf("xxx: '%s'\n", keyB64)
	f, err := os.Open(encfile)
	defer f.Close()
	if err != nil {
		t.Fatal("Couldn't open test file")
	}

	dec, err := NewDecryptReadSeeker(keyB64, st.Size(), f)
	if err != nil {
		t.Fatalf("%v", err)
	}
	// read the whole file
	decbytes := make([]byte, 1024*8-1) // weird size uncovers bugs
	pbytes := make([]byte, 1024*8-1)
	_, err = plainf.Seek(0, 0)
	_, err = dec.Seek(0, 0)

	ptext := make([]byte, 0)
	dectext := make([]byte, 0)
	counter := 0
	for {
		n, err := plainf.Read(pbytes)
		ptext = append(ptext, pbytes[:n]...)
		if err != nil {
			if err != io.EOF {
				t.Errorf("unexpected error %v", err)
			}
			break
		}
		counter++
	}

	counter = 0
	for {
		n, err := dec.Read(decbytes)
		dectext = append(dectext, decbytes[:n]...)
		if err != nil {
			if err != io.EOF {
				t.Errorf("unexpected error %v", err)
			}
			break
		}
		counter++
	}

	if len(dectext) != len(ptext) {
		t.Errorf("read lengths are different %v %v", len(dectext), len(ptext))
	}
	if len(dectext) != 5510872 {
		t.Errorf("unexpected size %d", len(dectext))
	}
	for i, b := range ptext {
		if dectext[i] != b {
			t.Errorf("unexpected byte %v %v", b, dectext[i])
			break
		}
	}
}
