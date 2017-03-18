//+build !gssapi

package mongosqlauth

import "github.com/go-sql-driver/mysql"

func gssapiClientFactory(username string, cfg *mysql.Config) saslClient {
	panic("GSSAPI support not enabled during build (-tags gssapi)")
}
