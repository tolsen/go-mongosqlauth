package mongosqlauth

type saslMechanism struct {
	nConvos       int
	username      string
	password      string
	clientFactory func(username, password string) saslClient

	clients []saslClient
}

func (m *saslMechanism) Next(challenge []byte) ([]byte, error) {

	var data []byte

	if len(m.clients) == 0 {
		// first time through

		for i := 0; i < m.nConvos; i++ {
			client := m.clientFactory(m.username, m.password)
			m.clients = append(m.clients, client)

			payload, err := client.Start()
			if err != nil {
				return nil, err
			}

			if client.Completed() {
				data = append(data, 1)
			} else {
				data = append(data, 0)
			}
			data = append(data, uint32ToBytes(uint32(len(payload)))...)
			data = append(data, payload...)
		}

		return data, nil
	}

	var err error
	pos := 0
	for i := 0; i < len(m.clients); i++ {
		payloadLen := int(bytesToUint32(challenge[pos : pos+4]))
		pos += 4
		payload := challenge[pos : pos+payloadLen]

		payload, err = m.clients[i].Next(payload)
		if err != nil {
			return nil, err
		}

		if m.clients[i].Completed() {
			data = append(data, 1)
		} else {
			data = append(data, 0)
		}
		data = append(data, uint32ToBytes(uint32(len(payload)))...)
		data = append(data, payload...)
	}

	return data, nil
}

type saslClient interface {
	Start() ([]byte, error)
	Next(challenge []byte) ([]byte, error)
	Completed() bool
}
