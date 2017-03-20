//+build gssapi,!windows

package mongosqlauth

import "github.com/go-sql-driver/mysql"

func gssapiClientFactory(address string, username string, cfg *mysql.Config) saslClient {
	panic("GSSAPI support not enabled for non-windows builds")
}
