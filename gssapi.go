//+build gssapi
//+build windows linux darwin

package mongosqlauth

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/10gen/go-mongosqlauth/internal/gssapi"
	"github.com/go-sql-driver/mysql"
)

func gssapiClientFactory(username string, props map[string]string, cfg *mysql.Config) saslClient {

	serviceName := "mongosql"
	canonicalizeHostName := false
	serviceRealm := ""
	var err error

	for key, value := range props {
		switch strings.ToUpper(key) {
		case "CANONICALIZE_HOST_NAME":
			canonicalizeHostName, err = strconv.ParseBool(value)
			if err != nil {
				panic(fmt.Sprintf("%s must be a boolean (true, false, 0, 1) but got '%s'", key, value))
			}

		case "SERVICE_REALM":
			serviceRealm = value
		case "SERVICE_NAME":
			serviceName = value
		}
	}

	c, err := gssapi.New(cfg.Addr, username, cfg.Passwd, cfg.Passwd != "", serviceName, canonicalizeHostName, serviceRealm)
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
