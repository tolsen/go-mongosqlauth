package mongosqlauth_test

import (
	"database/sql"
	"testing"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/tolsen/go-mongosqlauth"
)

func TestScramSha1(t *testing.T) {
	db, err := sql.Open("mysql", "jack:pass@tcp(localhost:3307)/test")
	if err != nil {
		t.Fatalf("unable to connect")
	}

	err = db.Ping()
	if err != nil {
		t.Fatalf("unable to ping: %v", err)
	}
}
