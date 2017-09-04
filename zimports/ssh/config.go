package ssh

func MakeSSHConfig() *ClientConfig {
	ret := new(ClientConfig)
	ret.DontAuthenticate = true // IOT scan ethically, never attempt to authenticate
	ret.HostKeyAlgorithms = supportedHostKeyAlgos
	ret.KeyExchanges = defaultKexAlgos
	ret.Ciphers = defaultCiphers
	return ret
}
