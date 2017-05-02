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
	initiated bool
	mech      mechanism
}

type mechanism interface {
	Next([]byte) ([]byte, error)
}

func (m *plugin) Close() {}

func (p *plugin) Next(challenge []byte) ([]byte, error) {

	if p.mech != nil {
		return p.mech.Next(challenge)
	}

	if !p.initiated {
		// first time through, challenge will include
		// plugin version in the first 2 bytes.
		if challenge[0] != 1 {
			return nil, fmt.Errorf("only mongosql_auth plugin version 1.x is supported")
		}
		p.initiated = true
		return nil, nil
	}

	// second time through, challenge will include the mechanism to use along with mechanism
	// specific information.
	mechEnd := bytes.IndexByte(challenge, 0)
	if mechEnd == -1 {
		return nil, fmt.Errorf("invalid auth response: not null terminator found")
	}

	pos := 0
	mechanism := string(challenge[:mechEnd])
	pos += mechEnd + 1
	nConvos := int(bytesToUint32(challenge[mechEnd+1 : mechEnd+5]))
	pos += 4

	username, props, err := p.parseUsername()
	if err != nil {
		return nil, err
	}

	switch mechanism {
	case "GSSAPI":
		p.mech = &saslMechanism{
			nConvos: nConvos,

			clientFactory: func() saslClient {
				return gssapiClientFactory(username, props, p.cfg)
			},
		}
	case "SCRAM-SHA-1":
		p.mech = &saslMechanism{
			nConvos: nConvos,

			clientFactory: func() saslClient {
				return &scramSaslClient{
					username: username,
					password: p.cfg.Passwd,
				}
			},
		}
	case "PLAIN":
		p.mech = &saslMechanism{
			nConvos: nConvos,

			clientFactory: func() saslClient {
				return &plainSaslClient{
					username: username,
					password: p.cfg.Passwd,
				}
			},
		}
	default:
		return nil, fmt.Errorf("unsupported mechanism: %s", mechanism)
	}

	return p.mech.Next(nil)
}

func (p *plugin) parseUsername() (username string, props map[string]string, err error) {
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
			case "mechanismProperties":
				props = make(map[string]string)
				pairs := strings.Split(value[0], ",")
				for _, pair := range pairs {
					kv := strings.SplitN(pair, ":", 2)
					if len(kv) != 2 || kv[0] == "" {
						err = fmt.Errorf("invalid mechanism property")
						return
					}
					props[kv[0]] = kv[1]
				}
			}
		}
	}

	return
}
