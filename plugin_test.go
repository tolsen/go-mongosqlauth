package mongosqlauth_test

import (
	"database/sql"
	"testing"

	_ "github.com/10gen/go-mongosqlauth"
	_ "github.com/go-sql-driver/mysql"
)

func TestMongoDBCR(t *testing.T) {

	db, err := sql.Open("mysql", "root?mechanism=MONGODB-CR:test@tcp(localhost:3307)/test")
	if err != nil {
		t.Fatalf("unable to connect")
	}

	err = db.Ping()
	if err != nil {
		t.Fatalf("unable to ping: %v", err)
	}
}

func TestScramSha1(t *testing.T) {

	db, err := sql.Open("mysql", "root?source=test&mechanism=SCRAM-SHA-1:test@tcp(localhost:3307)/test")
	if err != nil {
		t.Fatalf("unable to connect")
	}

	err = db.Ping()
	if err != nil {
		t.Fatalf("unable to ping: %v", err)
	}

}
