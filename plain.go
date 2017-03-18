package mongosqlauth

import "fmt"

type plainSaslClient struct {
	username string
	password string
}

func (c *plainSaslClient) Start() ([]byte, error) {
	b := []byte("\x00" + c.username + "\x00" + c.password)
	return b, nil
}

func (c *plainSaslClient) Next(challenge []byte) ([]byte, error) {
	return nil, fmt.Errorf("unexpected server challenge")
}

func (c *plainSaslClient) Completed() bool {
	return true
}
