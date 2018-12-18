package info

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/timothyham/bbackup/config"
)

const (
	timeformat      = time.RFC3339
	InfoTableName   = "info"
	ConfigTableName = "config"
	selectQuery     = "select id, name, modified, size, perms, user, encname, encformat, key, iv, sha1, sha256, encsha1, encsha256" +
		" from " + InfoTableName
)

var NoResultError = errors.New("no results")

type Info struct {
	ID       int64
	Name     string
	Modified time.Time
	Size     int64
	Perms    int
	User     int

	Encname   string
	EncFormat int
	Key       string
	IV        string

	SHA1      string
	SHA256    string
	EncSHA1   string
	EncSHA256 string
}

type Db struct {
	dbPath string
	db     *sql.DB
}

func NewDb(dbPath string) *Db {
	db := Db{}
	db.dbPath = dbPath

	sqlite, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		config.Logger.Fatal(err)
		return nil
	}
	db.db = sqlite
	err = db.createTableIfNotExists()
	if err != nil {
		config.Logger.Fatal(err)
		return nil
	}
	return &db
}

func (db *Db) createTableIfNotExists() error {
	query := "create table if not exists " + InfoTableName +
		" (id integer not null primary key, " +
		"name text, " +
		"modified text, " +
		"size integer, " +
		"perms integer, " +
		"user integer, " +
		"encname text, " +
		"encformat integer, " +
		"key text, " +
		"iv text, " +
		"sha1 integer, " +
		"sha256 integer, " +
		"encsha1 text, " +
		"encsha256 text " +
		");"

	_, err := db.db.Exec(query)
	if err != nil {
		return err
	}

	query2 := "create table if not exists " + ConfigTableName +
		" (id integer not null primary key, " +
		"key text, " +
		"value text " +
		");"

	_, err = db.db.Exec(query2)
	if err != nil {
		return err
	}

	return nil
}

func (db *Db) Insert(m *Info) error {
	query := ""
	if m.ID == 0 {
		query = "insert into " + InfoTableName +
			" (name, modified, size, perms, user, encname, encformat, key, iv, sha1, sha256, encsha1, encsha256) values " +
			"(?,?,?,?,?,?,?,?,?,?,?,?,?)"
		err := db.execPreparedStmt(query,
			m.Name, toModtime(m.Modified), m.Size, m.Perms, m.User, m.Encname, m.EncFormat,
			m.Key, m.IV, m.SHA1, m.SHA256, m.EncSHA1, m.EncSHA256)
		return err
	} else {
		return db.Update(m)
	}
}

// rowsToInfo converts a row into info and closes the row
func (db *Db) rowsToInfo(rows *sql.Rows) (*Info, error) {
	var id, size int64
	var perms, user, encformat int
	var name, modified, encname, key, iv, sha1, sha256, encsha1, encsha256 string

	var err error
	if rows.Next() {
		err = rows.Scan(&id, &name, &modified, &size, &perms, &user,
			&encname, &encformat, &key, &iv, &sha1, &sha256, &encsha1, &encsha256)
	} else {
		return nil, NoResultError
	}
	err = rows.Err()
	modtime := toTime(modified)
	info := &Info{ID: id, Name: name, Modified: modtime, Size: size, Perms: perms,
		User: user, Encname: encname, EncFormat: encformat,
		Key: key, IV: iv, SHA1: sha1, SHA256: sha256, EncSHA1: encsha1, EncSHA256: encsha256,
	}
	return info, err
}

func (db *Db) rowsToInfos(rows *sql.Rows) ([]*Info, error) {
	result := make([]*Info, 0)
	var err error
	var info *Info
	for {
		info, err = db.rowsToInfo(rows)
		if info != nil {
			result = append(result, info)
		} else {
			if err == NoResultError {
				err = nil
			}
			break
		}
	}
	return result, err
}

func (db *Db) GetByEncname(encname string) (*Info, error) {
	query := selectQuery + " where encname = ?"

	rows, err := db.execPreparedQuery(query, encname)
	if err != nil {
		return nil, err
	}
	info, err := db.rowsToInfo(rows)
	if rows != nil {
		rows.Close()
	}
	return info, err
}

func (db *Db) GetByName(name string) (*Info, error) {
	query := selectQuery + " where name = ?"

	rows, err := db.execPreparedQuery(query, name)
	if err != nil {
		return nil, err
	}
	info, err := db.rowsToInfo(rows)
	if rows != nil {
		rows.Close()
	}
	return info, err
}

func (db *Db) GetById(sid string) (*Info, error) {
	query := selectQuery + " where id = ?"

	id, err := strconv.Atoi(sid)
	if err != nil {
		return nil, err
	}
	rows, err := db.execPreparedQuery(query, id)
	if err != nil {
		return nil, err
	}
	info, err := db.rowsToInfo(rows)
	if rows != nil {
		rows.Close()
	}
	return info, err
}

func (db *Db) Update(m *Info) error {
	query := "update " + InfoTableName +
		" set (name, modified, size, perms, user, encname, encformat, key, iv, " +
		"sha1, sha256, encsha1, encsha256) = " +
		"(?,?,?,?,?,?,?,?,?,?,?,?,?) where id = ?"
	err := db.execPreparedStmt(query, m.Name, toModtime(m.Modified), m.Size, m.Perms,
		m.User, m.Encname, m.EncFormat, m.Key, m.IV, m.SHA1, m.SHA256, m.EncSHA1, m.EncSHA256,
		m.ID)
	return err
}

func (db *Db) Delete(m *Info) error {
	query := "delete from " + InfoTableName + " where id = ?"
	err := db.execPreparedStmt(query, m.ID)
	return err
}

func (db *Db) GetAll() ([]*Info, error) {
	query := selectQuery + " order by name collate nocase asc"

	rows, err := db.execPreparedQuery(query)

	if err != nil {
		return nil, err
	}

	infos, err := db.rowsToInfos(rows)

	rows.Close()
	return infos, err
}

func (db *Db) GetPrefixName(prefix string) ([]*Info, error) {
	query := selectQuery + " where name like ? order by name asc"

	rows, err := db.execPreparedQuery(query, prefix+"%")
	defer rows.Close()
	if err != nil {
		fmt.Printf("db error %v\n", err)
		return nil, err
	}

	infos := make([]*Info, 0)
	var info *Info
	for rows.Next() {
		info, err = db.rowsToInfo(rows)
		infos = append(infos, info)
	}

	return infos, err
}

func toModtime(t time.Time) string {
	return t.Format(timeformat)
}

func toTime(s string) time.Time {
	modtime, _ := time.Parse(timeformat, s)
	return modtime
}
func (db *Db) execPreparedStmt(query string, args ...interface{}) error {
	tx, err := db.db.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()
	stmt.Exec(args...)
	err = tx.Commit()
	return err
}

func (db *Db) execPreparedQuery(query string, args ...interface{}) (*sql.Rows, error) {
	stmt, err := db.db.Prepare(query)
	if err != nil {
		return nil, err
	}
	rows, err := stmt.Query(args...)
	if err != nil {
		return nil, err
	}
	return rows, err
}
