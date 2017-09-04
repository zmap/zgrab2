package ssh

import (
	"errors"
	"fmt"
	"strings"
)

type SSHConfig struct {
	ClientID          string
	HostKeyAlgorithms HostKeyAlgorithmsList
	KexAlgorithms     KexAlgorithmsList
	Verbose           bool
	CollectUserAuth   bool
	Ciphers           CipherList
	GexMinBits        uint
	GexMaxBits        uint
	GexPreferredBits  uint
}

type HostKeyAlgorithmsList struct {
	Algorithms []string
}

func (hkaList *HostKeyAlgorithmsList) String() string {
	return strings.Join(hkaList.Algorithms, ",")
}

func (hkaList *HostKeyAlgorithmsList) Set(value string) error {
	for _, alg := range strings.Split(value, ",") {
		isValid := false
		for _, val := range supportedHostKeyAlgos {
			if val == alg {
				isValid = true
				break
			}
		}

		if !isValid {
			return errors.New(fmt.Sprintf(`host key algorithm not supported: "%s"`, alg))
		}

		hkaList.Algorithms = append(hkaList.Algorithms, alg)
	}
	return nil
}

func (hkaList *HostKeyAlgorithmsList) Get() []string {
	if len(hkaList.Algorithms) == 0 {
		return supportedHostKeyAlgos
	} else {
		return hkaList.Algorithms
	}
}

type KexAlgorithmsList struct {
	Algorithms []string
}

func (kaList *KexAlgorithmsList) String() string {
	return strings.Join(kaList.Algorithms, ",")
}

func (kaList *KexAlgorithmsList) Set(value string) error {
	for _, alg := range strings.Split(value, ",") {
		isValid := false
		for _, val := range allSupportedKexAlgos {
			if val == alg {
				isValid = true
				break
			}
		}

		if !isValid {
			return errors.New(fmt.Sprintf(`DH KEX algorithm not supported: "%s"`, alg))
		}

		kaList.Algorithms = append(kaList.Algorithms, alg)
	}
	return nil
}

func (kaList *KexAlgorithmsList) Get() []string {
	if len(kaList.Algorithms) == 0 {
		return defaultKexAlgos
	} else {
		return kaList.Algorithms
	}
}

type CipherList struct {
	Ciphers []string
}

func (cList *CipherList) String() string {
	return strings.Join(cList.Ciphers, ",")
}

func (cList *CipherList) Set(value string) error {
	for _, inCipher := range strings.Split(value, ",") {
		isValid := false
		for _, knownCipher := range allSupportedCiphers {
			if inCipher == knownCipher {
				isValid = true
				break
			}
		}

		if !isValid {
			return errors.New(fmt.Sprintf(`cipher not supported: "%s"`, inCipher))
		}

		cList.Ciphers = append(cList.Ciphers, inCipher)
	}

	return nil
}

func (cList *CipherList) Get() []string {
	if len(cList.Ciphers) == 0 {
		return defaultCiphers
	} else {
		return cList.Ciphers
	}
}
