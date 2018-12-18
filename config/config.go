package config

import (
	"log"
	"os"
)

var Logger *log.Logger
var Debug bool

func init() {
	Logger = log.New(os.Stdout, "bbackup:", log.Ldate|log.Ltime|log.Lshortfile)
}
