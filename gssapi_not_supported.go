//+build gssapi,!windows,!linux,!darwin

package mongosqlauth

import (
	"fmt"
	"runtime"

	"github.com/go-sql-driver/mysql"
)

func gssapiClientFactory(username string, props map[string]string, cfg *mysql.Config) saslClient {
	panic(fmt.Sprintf("GSSAPI is not supported on %s", runtime.GOOS))
}
