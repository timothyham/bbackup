package info

import (
	"os"
	"testing"
	"time"
)

var dbtest bool = true
var testdbname = "testdata/test.db"

func TestDbCrud(t *testing.T) {
	if !dbtest {
		return
	}

	os.Remove(testdbname)

	db := NewDb(testdbname)
	if db == nil {
		t.Errorf("No db created")
	}

	m1 := Info{}
	m1.IV = "1234"
	m1.Key = "keykey"
	m1.Encname = "abcdef"
	m1.Name = "origname"
	m1.EncSHA256 = "encsha256"
	m1.SHA256 = "sha256"
	m1.Size = 1234
	m1.Modified, _ = time.Parse(time.RFC3339, "2017-09-03T14:16:17-07:00")

	err := db.Insert(&m1)
	if err != nil {
		t.Fatalf("could not save: %s\n", err.Error())
	}

	m2, err := db.GetByEncname(m1.Encname)
	if err != nil {
		t.Errorf("%s", err)
	}
	if !m1.Modified.Equal(m2.Modified) {
		t.Errorf("Timestamps mismatch")
	}
	if m1.Size != m2.Size {
		t.Errorf("Unexpected %v\n", m2.Size)
	}

	m2, err = db.GetByName(m1.Name)
	if err != nil {
		t.Errorf("%s", err)
	}
	if m2.Name != m1.Name {
		t.Errorf("%s", err)
	}

	m2.Name = "newname"
	err = db.Update(m2)
	if err != nil {
		t.Errorf("Coould not update %v", err)
	}

	m3, err := db.GetByEncname(m2.Encname)
	if err != nil {
		t.Errorf("Could not get updated value %v\n", err)
	}
	if m2.Name != m3.Name {
		t.Errorf("Update failed %v", err)
	}

	all, err := db.GetAll()
	if err != nil || len(all) != 1 {
		t.Errorf("Fail: %v", err)
	}

	err = db.Delete(m2)
	if err != nil {
		t.Errorf("Could not delete %v", err)
	}

	_, err = db.GetByEncname(m2.Encname)
	if err != NoResultError {
		t.Errorf("Wrong error message")
	}
	if err == nil {
		t.Errorf("Should have failed")
	}

}
