package ssh

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
)

func (c *ClientConfig) SetKexAlgorithms(value string) error {
	var allSupportedKexAlgos []string
	allSupportedKexAlgos = append(allSupportedKexAlgos, supportedKexAlgos...)
	// serverForbiddenKexAlgos are supported for clients but not present in the supportedKexAlgos list
	allSupportedKexAlgos = append(allSupportedKexAlgos, slices.Collect(maps.Keys(serverForbiddenKexAlgos))...)
	algs, err := validateAlgorithms(value, allSupportedKexAlgos)
	if err != nil {
		return err
	}
	c.KeyExchanges = algs
	return nil
}

func (c *ClientConfig) SetHostKeyAlgorithms(value string) error {
	algs, err := validateAlgorithms(value, supportedHostKeyAlgos)
	if err != nil {
		return err
	}
	c.HostKeyAlgorithms = algs
	return nil
}

func (c *ClientConfig) SetCiphers(value string, allowUnsupported bool) error {
	var algs []string
	if allowUnsupported {
		algs = strings.Split(value, ",")
	} else {
		var err error
		algs, err = validateAlgorithms(value, supportedCiphers)
		if err != nil {
			return err
		}
	}
	c.Ciphers = algs
	return nil
}

func (c *ClientConfig) SetMACs(value string, allowUnsupported bool) error {
	var algs []string
	if allowUnsupported {
		algs = strings.Split(value, ",")
	} else {
		var err error
		algs, err = validateAlgorithms(value, supportedMACs)
		if err != nil {
			return err
		}
	}
	c.MACs = algs
	return nil
}

func (c *ClientConfig) SetCompressionAlgorithms(value string, allowUnsupported bool) error {
	var algs []string
	if allowUnsupported {
		algs = strings.Split(value, ",")
	} else {
		var err error
		algs, err = validateAlgorithms(value, supportedCompressions)
		if err != nil {
			return err
		}
	}
	c.CompressionAlgorithms = algs
	return nil
}

func validateAlgorithms(value string, supported []string) ([]string, error) {
	var algs []string
	for _, alg := range strings.Split(value, ",") {
		isValid := contains(supported, alg)
		if !isValid {
			return nil, errors.New(fmt.Sprintf(`algorithm not supported: "%s"`, alg))
		}
		algs = append(algs, alg)
	}
	return algs, nil
}
