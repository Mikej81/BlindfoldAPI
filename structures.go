package main

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
)

// App holds application-wide dependencies
type App struct {
	DB *sql.DB
}

type User struct {
	Username  string
	Role      string
	LastLogin string
	Uid       string
}

type APIToken struct {
	Token     string
	CreatedAt string
	Id        string
}
