//+build gssapi,windows

package mongosqlauth

import (
	"github.com/go-sql-driver/mysql"

	"github.com/10gen/go-mongosqlauth/internal/sspi"
)

func gssapiClientFactory(address, username string, cfg *mysql.Config) saslClient {
	c, err := sspi.New(address, username, cfg.Passwd, cfg.Passwd != "", nil)
	if err != nil {
		panic(err)
	}

	return c
}
