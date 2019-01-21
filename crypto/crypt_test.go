package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"os"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	ciphertextFile := "onemeg.enc"
	plaintext, err := os.Open("testdata/onemeg.txt")
	defer plaintext.Close()
	if err != nil {
		t.Error("Could not open file")
	}

	ciphertext, err := os.Create("testdata/" + ciphertextFile)
	if err != nil {
		t.Error("Could not open output file")
	}

	encryptor := NewEncryptor()
	keyHex := "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"
	key, _ := hex.DecodeString(keyHex)
	keyB64 := base64.RawURLEncoding.EncodeToString(key)
	encryptor.SetKey(keyB64)

	ivHex := "000102030405060708090a0b0c0d0e0f0001020304050607"
	iv, _ := hex.DecodeString(ivHex)
	ivB64 := base64.RawURLEncoding.EncodeToString(iv)
	encryptor.SetIv(ivB64)
	encryptor.Init()

	hash, err := encryptor.Encrypt(ciphertext, plaintext, true)
	if err != nil {
		t.Errorf("Error encrypting file: %v", err)
	}

	if hash.InSHA1 != "c19451af499dadf2d0f035ce36532e3fc3d6c172" {
		t.Errorf("wrong hash %s", hash.InSHA1)
	}
	if hash.InSHA256 != "9627a54a4bbabf51eaa39f6e9169e3364f0b4c54a1522f4ddfd6637384cc15de" {
		t.Errorf("wrong hash %s", hash.InSHA256)
	}
	if hash.OutSHA1 != "1a81793ad5a5b0ef5d668d21235950a724b1d3dd" {
		t.Errorf("wrong hash %s", hash.OutSHA1)
	}
	if hash.OutSHA256 != "3969fcfd5ba999c74d874cc1a5d42ea7a98bc5d5796caab3d4a201018af77544" {
		t.Errorf("wrong hash %s", hash.OutSHA256)
	}

	ciphertext.Sync()
	ciphertextStats, err := ciphertext.Stat()
	if err != nil {
		t.Errorf("Error getting ciphertext stats")
	}
	if ciphertextStats.Size() != int64(1024*1024+4*encryptor.Overhead)+int64(headerOffset) {
		t.Errorf("unexpected ciphertext size  %d", ciphertextStats.Size())
	}

	ciphertext.Close()

	decText, err := os.Create("testdata/onemeg.dec")
	defer decText.Close()
	if err != nil {
		t.Errorf("could not open decrypted file: %v", err)
	}
	ciphertext, err = os.Open("testdata/" + ciphertextFile)
	defer ciphertext.Close()
	if err != nil {
		t.Errorf("unexpected %v", err)
	}
	hash, err = encryptor.Encrypt(decText, ciphertext, false)
	if err != nil {
		t.Errorf("unexpected eror %v", err)
	}

	ori, err := ioutil.ReadFile("testdata/onemeg.txt")
	if err != nil {
		t.Errorf("unexpected %v", err)
	}
	dec, err := ioutil.ReadFile("testdata/onemeg.dec")
	if err != nil {
		t.Errorf("unexpected %v", err)
	}

	if len(ori) != len(dec) {
		t.Errorf("files are different sizes")
	}
	for i := 0; i < len(ori); i++ {
		if ori[i] != dec[i] {
			t.Error("enc and dec files are different")
		}
	}
}

func TestNewEncname(t *testing.T) {
	encname := NewEncname()
	if len(string(encname)) != 40 {
		t.Error("Did not generate encname")
	}
}
