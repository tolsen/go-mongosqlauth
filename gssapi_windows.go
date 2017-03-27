//+build gssapi,windows

package mongosqlauth

import (
	"fmt"

	"github.com/go-sql-driver/mysql"

	"net"

	"github.com/10gen/go-mongosqlauth/internal/sspi"
)

func gssapiClientFactory(username string, cfg *mysql.Config) saslClient {

	spn := fmt.Sprintf("mongosql/%s", getHostname(cfg.Addr))
	c, err := sspi.New(spn, username, cfg.Passwd, cfg.Passwd != "")
	if err != nil {
		panic(err)
	}

	return c
}

func getHostname(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}

	return addr
}
