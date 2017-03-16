package mongosqlauth

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"io"
)

type mongoDBCRMechanism struct {
	nConvos  int
	username string
	password string

	step int
}

func (m *mongoDBCRMechanism) Next(challenge []byte) ([]byte, error) {
	m.step++
	switch m.step {
	case 1:
		// nothing to do. We need nonces.
		return nil, nil
	case 2:
		// read nonces
		i := 0
		resp := []byte{}
		for i < m.nConvos && len(challenge) > 0 {
			nonceEnd := bytes.IndexByte(challenge, 0)
			if nonceEnd == -1 {
				return nil, fmt.Errorf("expected nul terminator, but found none")
			}

			nonce := string(challenge[:nonceEnd])
			key := m.createKey(nonce)

			resp = append(resp, []byte(key)...)
			resp = append(resp, 0)

			challenge = challenge[nonceEnd+1:]
			i++
		}

		if i != m.nConvos || len(challenge) > 0 {
			return nil, fmt.Errorf("conversation count was incorrect")
		}

		return resp, nil

	default:
		return nil, fmt.Errorf("unexpected challenge")
	}
}

func (m *mongoDBCRMechanism) createKey(nonce string) string {
	h := md5.New()

	io.WriteString(h, nonce)
	io.WriteString(h, m.username)
	io.WriteString(h, mongoPasswordDigest(m.username, m.password))
	return fmt.Sprintf("%x", h.Sum(nil))
}
