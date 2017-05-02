package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"

	_ "github.com/10gen/go-mongosqlauth"
	_ "github.com/go-sql-driver/mysql"
)

var dsn = flag.String("dsn", "client%40WHOME.LOCAL?mechanism=GSSAPI:password@tcp(sikai.whome.local.net:3307)/test", "")

func main() {

	flag.Parse()

	fmt.Println("connecting to", *dsn)

	db, err := sql.Open("mysql", *dsn)
	if err != nil {
		log.Fatalf("unable to connect: %v", err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatalf("unable to ping: %v", err)
	}
}
