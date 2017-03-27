package mongosqlauth_test

import (
	"database/sql"
	"testing"

	_ "github.com/10gen/go-mongosqlauth"
	_ "github.com/go-sql-driver/mysql"
)

func TestScramSha1(t *testing.T) {
	db, err := sql.Open("mysql", "blah")
	if err != nil {
		t.Fatalf("unable to connect")
	}

	err = db.Ping()
	if err != nil {
		t.Fatalf("unable to ping: %v", err)
	}
}
