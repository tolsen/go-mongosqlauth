package mongosqlauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"math/rand"
	"strconv"

	"golang.org/x/crypto/pbkdf2"

	"strings"

	"encoding/base64"
)

const scramSHA1NonceLen = 24

var usernameSanitizer = strings.NewReplacer("=", "=3D", ",", "=2C")

type scramSaslClient struct {
	username       string
	password       string
	mechanism      string
	nonceGenerator func([]byte) error

	step                   uint8
	clientNonce            []byte
	clientFirstMessageBare string
	serverSignature        []byte
}

func (c *scramSaslClient) Start() (string, []byte, error) {
	if err := c.generateClientNonce(scramSHA1NonceLen); err != nil {
		return c.mechanism, nil, err
	}

	c.clientFirstMessageBare = "n=" + usernameSanitizer.Replace(c.username) + ",r=" + string(c.clientNonce)

	return c.mechanism, []byte("n,," + c.clientFirstMessageBare), nil
}

func (c *scramSaslClient) Next(challenge []byte) ([]byte, error) {
	c.step++
	switch c.step {
	case 1:
		return c.step1(challenge)
	case 2:
		return c.step2(challenge)
	default:
		return nil, fmt.Errorf("unexpected server challenge")
	}
}

func (c *scramSaslClient) Completed() bool {
	return c.step >= 2
}

func (c *scramSaslClient) step1(challenge []byte) ([]byte, error) {
	fields := bytes.Split(challenge, []byte{','})
	if len(fields) != 3 {
		return nil, fmt.Errorf("invalid server response")
	}

	if !bytes.HasPrefix(fields[0], []byte("r=")) || len(fields[0]) < 2 {
		return nil, fmt.Errorf("invalid nonce")
	}
	r := fields[0][2:]
	if !bytes.HasPrefix(r, c.clientNonce) {
		return nil, fmt.Errorf("invalid nonce")
	}

	if !bytes.HasPrefix(fields[1], []byte("s=")) || len(fields[1]) < 6 {
		return nil, fmt.Errorf("invalid salt")
	}
	s := make([]byte, base64.StdEncoding.DecodedLen(len(fields[1][2:])))
	n, err := base64.StdEncoding.Decode(s, fields[1][2:])
	if err != nil {
		return nil, fmt.Errorf("invalid salt")
	}
	s = s[:n]

	if !bytes.HasPrefix(fields[2], []byte("i=")) || len(fields[2]) < 3 {
		return nil, fmt.Errorf("invalid iteration count")
	}
	i, err := strconv.Atoi(string(fields[2][2:]))
	if err != nil {
		return nil, fmt.Errorf("invalid iteration count")
	}
	if c.mechanism == "SCRAM-SHA-256" && i < 4096 {
		return nil, fmt.Errorf("server returned an invalid iteration count")
	}

	var saltedPassword []byte
	if c.mechanism == "SCRAM-SHA-1" {
		saltedPassword = pbkdf2.Key([]byte(mongoPasswordDigest(c.username, c.password)), s, i, 20, sha1.New)
	} else {
		// SHA-256
		saltedPassword, err = c.saltSha256Password(s, i)
		if err != nil {
			return nil, err
		}
	}
	clientFinalMessageWithoutProof := "c=biws,r=" + string(r)
	authMessage := c.clientFirstMessageBare + "," + string(challenge) + "," + clientFinalMessageWithoutProof

	clientKey := c.hmac(saltedPassword, "Client Key")
	storedKey := c.h(clientKey)
	clientSignature := c.hmac(storedKey, authMessage)
	clientProof := c.xor(clientKey, clientSignature)
	serverKey := c.hmac(saltedPassword, "Server Key")
	c.serverSignature = c.hmac(serverKey, authMessage)

	proof := "p=" + base64.StdEncoding.EncodeToString(clientProof)
	clientFinalMessage := clientFinalMessageWithoutProof + "," + proof

	return []byte(clientFinalMessage), nil
}

func (c *scramSaslClient) step2(challenge []byte) ([]byte, error) {
	var hasV, hasE bool
	fields := bytes.Split(challenge, []byte{','})
	if len(fields) == 1 {
		hasV = bytes.HasPrefix(fields[0], []byte("v="))
		hasE = bytes.HasPrefix(fields[0], []byte("e="))
	}
	if hasE {
		return nil, fmt.Errorf(string(fields[0][2:]))
	}
	if !hasV {
		return nil, fmt.Errorf("invalid final message")
	}

	v := make([]byte, base64.StdEncoding.DecodedLen(len(fields[0][2:])))
	n, err := base64.StdEncoding.Decode(v, fields[0][2:])
	if err != nil {
		return nil, fmt.Errorf("invalid server verification")
	}
	v = v[:n]

	if !bytes.Equal(c.serverSignature, v) {
		return nil, fmt.Errorf("invalid server signature")
	}

	return nil, nil
}

func (c *scramSaslClient) saltSha256Password(salt []byte, iterCount int) ([]byte, error) {
	mac := hmac.New(sha256.New, []byte(c.password))
	_, err := mac.Write(salt)
	if err != nil {
		return nil, err
	}
	_, err = mac.Write([]byte{0, 0, 0, 1})
	if err != nil {
		return nil, err
	}
	ui := mac.Sum(nil)
	hi := make([]byte, len(ui))
	copy(hi, ui)
	for i := 1; i < iterCount; i++ {
		mac.Reset()
		_, err = mac.Write(ui)
		if err != nil {
			return nil, err
		}
		mac.Sum(ui[:0])
		for j, b := range ui {
			hi[j] ^= b
		}
	}
	return hi, nil
}

func (c *scramSaslClient) generateClientNonce(n uint8) error {
	if c.nonceGenerator != nil {
		c.clientNonce = make([]byte, n)
		return c.nonceGenerator(c.clientNonce)
	}

	buf := make([]byte, n)
	rand.Read(buf)

	c.clientNonce = make([]byte, base64.StdEncoding.EncodedLen(int(n)))
	base64.StdEncoding.Encode(c.clientNonce, buf)
	return nil
}

func (c *scramSaslClient) h(data []byte) []byte {
	h := c.getHashFunction()()
	h.Write(data)
	return h.Sum(nil)
}

func (c *scramSaslClient) hmac(data []byte, key string) []byte {
	h := hmac.New(c.getHashFunction(), data)
	io.WriteString(h, key)
	return h.Sum(nil)
}

func (c *scramSaslClient) xor(a []byte, b []byte) []byte {
	result := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}

func (c *scramSaslClient) getHashFunction() func() hash.Hash {
	if c.mechanism == "SCRAM-SHA-1" {
		return sha1.New
	}
	return sha256.New
}
