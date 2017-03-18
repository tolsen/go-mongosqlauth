package mongosqlauth

import (
	"fmt"
	"net/url"
	"strings"

	"bytes"

	"github.com/go-sql-driver/mysql"
)

func init() {
	mysql.RegisterAuthPlugin("mongosql_auth", func(cfg *mysql.Config) mysql.AuthPlugin {
		return &plugin{cfg: cfg}
	})
}

type plugin struct {
	cfg *mysql.Config

	// state
	mech mechanism
}

type mechanism interface {
	Next([]byte) ([]byte, error)
}

func (p *plugin) Next(challenge []byte) ([]byte, error) {

	if p.mech != nil {
		return p.mech.Next(challenge)
	}

	// first challenge will include the default mechanism and the number of conversations
	// to have.

	if len(challenge) == 0 {
		return nil, fmt.Errorf("invalid auth response: empty")
	}

	mechEnd := bytes.IndexByte(challenge, 0)
	if mechEnd == -1 {
		return nil, fmt.Errorf("invalid auth response: not null terminator found")
	}

	defaultMechName := string(challenge[:mechEnd])
	nConvos := int(bytesToUint32(challenge[mechEnd+1 : mechEnd+5]))

	username, mechName, err := p.parseUsername()
	if err != nil {
		return nil, err
	}

	if mechName == "" {
		mechName = defaultMechName
	}

	switch mechName {
	case "SCRAM-SHA-1":
		p.mech = &saslMechanism{
			nConvos:  nConvos,
			username: username,
			password: p.cfg.Passwd,

			clientFactory: func(username, password string) saslClient {
				return &scramSaslClient{
					username: username,
					password: password,
				}
			},
		}
	case "PLAIN":
		p.mech = &saslMechanism{
			nConvos:  nConvos,
			username: username,
			password: p.cfg.Passwd,

			clientFactory: func(username, password string) saslClient {
				return &plainSaslClient{
					username: username,
					password: password,
				}
			},
		}
	default:
		return nil, fmt.Errorf("unsupported mechanism: %s", mechName)
	}

	return p.mech.Next(nil)
}

func (p *plugin) parseUsername() (username string, mechanism string, err error) {
	username = p.cfg.User

	// parse user for extra information other than just the username
	// format is username?mechanism=PLAIN&source=db. This is the same
	// as a query string, so everything should be url encoded.
	idx := strings.Index(username, "?")
	if idx > 0 {
		username, err = url.QueryUnescape(p.cfg.User[:idx])
		if err != nil {
			return
		}
		var values url.Values
		values, err = url.ParseQuery(p.cfg.User[idx+1:])
		if err != nil {
			return
		}
		for key, value := range values {
			switch strings.ToLower(key) {
			case "mechanism":
				mechanism = value[0]
			}
		}
	}

	return
}
