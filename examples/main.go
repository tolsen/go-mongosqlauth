package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"

	_ "github.com/10gen/go-mongosqlauth"
	_ "github.com/go-sql-driver/mysql"
)

var host = flag.String("host", "localhost:27017", "")
var user = flag.String("user", "", "")
var pwd = flag.String("pwd", "", "")

func main() {

	flag.Parse()

	var cs string
	if *pwd != "" {
		cs = fmt.Sprintf("%s:%s@tcp(%s)/test", *user, *pwd, *host)
	} else {
		cs = fmt.Sprintf("tcp(%s)/test", *host)
	}

	fmt.Println("connecting to", cs)

	db, err := sql.Open("mysql", cs)
	if err != nil {
		log.Fatalf("unable to connect: %v", err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatalf("unable to ping: %v", err)
	}
}
