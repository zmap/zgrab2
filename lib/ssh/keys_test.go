// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/zmap/zcrypto/dsa"
	"golang.org/x/crypto/ed25519"

	"github.com/zmap/zgrab2/lib/ssh/testdata"
)

func rawKey(pub PublicKey) any {
	switch k := pub.(type) {
	case *rsaPublicKey:
		return (*rsa.PublicKey)(k)
	case *dsaPublicKey:
		return (*dsa.PublicKey)(k)
	case *ecdsaPublicKey:
		return (*ecdsa.PublicKey)(k)
	case ed25519PublicKey:
		return (ed25519.PublicKey)(k)
	case *Certificate:
		return k
	}
	panic("unknown key type")
}

func TestKeyMarshalParse(t *testing.T) {
	for _, priv := range testSigners {
		pub := priv.PublicKey()
		roundtrip, err := ParsePublicKey(pub.Marshal())
		if err != nil {
			t.Errorf("ParsePublicKey(%T): %v", pub, err)
		}

		k1 := rawKey(pub)
		k2 := rawKey(roundtrip)

		if !reflect.DeepEqual(k1, k2) {
			t.Errorf("got %#v in roundtrip, want %#v", k2, k1)
		}
	}
}

func TestUnsupportedCurves(t *testing.T) {
	raw, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	if _, err = NewSignerFromKey(raw); err == nil || !strings.Contains(err.Error(), "only P-256") {
		t.Fatalf("NewPrivateKey should not succeed with P-224, got: %v", err)
	}

	if _, err = NewPublicKey(&raw.PublicKey); err == nil || !strings.Contains(err.Error(), "only P-256") {
		t.Fatalf("NewPublicKey should not succeed with P-224, got: %v", err)
	}
}

func TestNewPublicKey(t *testing.T) {
	for _, k := range testSigners {
		raw := rawKey(k.PublicKey())
		// Skip certificates, as NewPublicKey does not support them.
		if _, ok := raw.(*Certificate); ok {
			continue
		}
		pub, err := NewPublicKey(raw)
		if err != nil {
			t.Errorf("NewPublicKey(%#v): %v", raw, err)
		}
		if !reflect.DeepEqual(k.PublicKey(), pub) {
			t.Errorf("NewPublicKey(%#v) = %#v, want %#v", raw, pub, k.PublicKey())
		}
	}
}

func TestKeySignVerify(t *testing.T) {
	for _, priv := range testSigners {
		pub := priv.PublicKey()

		data := []byte("sign me")
		sig, err := priv.Sign(rand.Reader, data)
		if err != nil {
			t.Fatalf("Sign(%T): %v", priv, err)
		}

		if err := pub.Verify(data, sig); err != nil {
			t.Errorf("publicKey.Verify(%T): %v", priv, err)
		}
		sig.Blob[5]++
		if err := pub.Verify(data, sig); err == nil {
			t.Errorf("publicKey.Verify on broken sig did not fail")
		}
	}
}

func TestKeySignWithAlgorithmVerify(t *testing.T) {
	for _, priv := range testSigners {
		if algorithmSigner, ok := priv.(AlgorithmSigner); !ok {
			t.Errorf("Signers constructed by ssh package should always implement the AlgorithmSigner interface: %T", priv)
		} else {
			pub := priv.PublicKey()
			data := []byte("sign me")

			signWithAlgTestCase := func(algorithm string, expectedAlg string) {
				sig, err := algorithmSigner.SignWithAlgorithm(rand.Reader, data, algorithm)
				if err != nil {
					t.Fatalf("Sign(%T): %v", priv, err)
				}
				if sig.Format != expectedAlg {
					t.Errorf("signature format did not match requested signature algorithm: %s != %s", sig.Format, expectedAlg)
				}

				if err := pub.Verify(data, sig); err != nil {
					t.Errorf("publicKey.Verify(%T): %v", priv, err)
				}
				sig.Blob[5]++
				if err := pub.Verify(data, sig); err == nil {
					t.Errorf("publicKey.Verify on broken sig did not fail")
				}
			}

			// Using the empty string as the algorithm name should result in the same signature format as the algorithm-free Sign method.
			defaultSig, err := priv.Sign(rand.Reader, data)
			if err != nil {
				t.Fatalf("Sign(%T): %v", priv, err)
			}
			signWithAlgTestCase("", defaultSig.Format)

			// RSA keys are the only ones which currently support more than one signing algorithm
			if pub.Type() == KeyAlgoRSA {
				for _, algorithm := range []string{KeyAlgoRSA, KeyAlgoRSASHA256, KeyAlgoRSASHA512} {
					signWithAlgTestCase(algorithm, algorithm)
				}
			}
		}
	}
}

func TestParseRSAPrivateKey(t *testing.T) {
	key := testPrivateKeys["rsa"]

	rsa, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("got %T, want *rsa.PrivateKey", rsa)
	}

	if err := rsa.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestParseECPrivateKey(t *testing.T) {
	key := testPrivateKeys["ecdsa"]

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("got %T, want *ecdsa.PrivateKey", ecKey)
	}

	if !validateECPublicKey(ecKey.Curve, ecKey.X, ecKey.Y) {
		t.Fatalf("public key does not validate.")
	}
}

func TestParseEncryptedPrivateKeysWithPassphrase(t *testing.T) {
	data := []byte("sign me")
	for _, tt := range testdata.PEMEncryptedKeys {
		t.Run(tt.Name, func(t *testing.T) {
			_, err := ParsePrivateKeyWithPassphrase(tt.PEMBytes, []byte("incorrect"))
			if err != x509.IncorrectPasswordError {
				t.Errorf("got %v want IncorrectPasswordError", err)
			}

			s, err := ParsePrivateKeyWithPassphrase(tt.PEMBytes, []byte(tt.EncryptionKey))
			if err != nil {
				t.Fatalf("ParsePrivateKeyWithPassphrase returned error: %s", err)
			}

			sig, err := s.Sign(rand.Reader, data)
			if err != nil {
				t.Fatalf("Signer.Sign: %v", err)
			}
			if err := s.PublicKey().Verify(data, sig); err != nil {
				t.Errorf("Verify failed: %v", err)
			}

			_, err = ParsePrivateKey(tt.PEMBytes)
			if err == nil {
				t.Fatalf("ParsePrivateKey succeeded, expected an error")
			}

			if err, ok := err.(*PassphraseMissingError); !ok {
				t.Errorf("got error %q, want PassphraseMissingError", err)
			} else if tt.IncludesPublicKey {
				if err.PublicKey == nil {
					t.Fatalf("expected PassphraseMissingError.PublicKey not to be nil")
				}
				got, want := err.PublicKey.Marshal(), s.PublicKey().Marshal()
				if !bytes.Equal(got, want) {
					t.Errorf("error field %q doesn't match signer public key %q", got, want)
				}
			}
		})
	}
}

func TestParseDSA(t *testing.T) {
	// We actually exercise the ParsePrivateKey codepath here, as opposed to
	// using the ParseRawPrivateKey+NewSignerFromKey path that testdata_test.go
	// uses.
	s, err := ParsePrivateKey(testdata.PEMBytes["dsa"])
	if err != nil {
		t.Fatalf("ParsePrivateKey returned error: %s", err)
	}

	data := []byte("sign me")
	sig, err := s.Sign(rand.Reader, data)
	if err != nil {
		t.Fatalf("dsa.Sign: %v", err)
	}

	if err := s.PublicKey().Verify(data, sig); err != nil {
		t.Errorf("Verify failed: %v", err)
	}
}

// Tests for authorized_keys parsing.

// getTestKey returns a public key, and its base64 encoding.
func getTestKey() (PublicKey, string) {
	k := testPublicKeys["rsa"]

	b := &bytes.Buffer{}
	e := base64.NewEncoder(base64.StdEncoding, b)
	e.Write(k.Marshal())
	e.Close()

	return k, b.String()
}

func TestMarshalParsePublicKey(t *testing.T) {
	pub, pubSerialized := getTestKey()
	line := fmt.Sprintf("%s %s user@host", pub.Type(), pubSerialized)

	authKeys := MarshalAuthorizedKey(pub)
	actualFields := strings.Fields(string(authKeys))
	if len(actualFields) == 0 {
		t.Fatalf("failed authKeys: %v", authKeys)
	}

	// drop the comment
	expectedFields := strings.Fields(line)[0:2]

	if !reflect.DeepEqual(actualFields, expectedFields) {
		t.Errorf("got %v, expected %v", actualFields, expectedFields)
	}

	actPub, _, _, _, err := ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatalf("cannot parse %v: %v", line, err)
	}
	if !reflect.DeepEqual(actPub, pub) {
		t.Errorf("got %v, expected %v", actPub, pub)
	}
}

type testAuthResult struct {
	pubKey   PublicKey
	options  []string
	comments string
	rest     string
	ok       bool
}

func testAuthorizedKeys(t *testing.T, authKeys []byte, expected []testAuthResult) {
	rest := authKeys
	var values []testAuthResult
	for len(rest) > 0 {
		var r testAuthResult
		var err error
		r.pubKey, r.comments, r.options, rest, err = ParseAuthorizedKey(rest)
		r.ok = (err == nil)
		t.Log(err)
		r.rest = string(rest)
		values = append(values, r)
	}

	if !reflect.DeepEqual(values, expected) {
		t.Errorf("got %#v, expected %#v", values, expected)
	}
}

func TestAuthorizedKeyBasic(t *testing.T) {
	pub, pubSerialized := getTestKey()
	line := "ssh-rsa " + pubSerialized + " user@host"
	testAuthorizedKeys(t, []byte(line),
		[]testAuthResult{
			{pub, nil, "user@host", "", true},
		})
}

func TestAuth(t *testing.T) {
	pub, pubSerialized := getTestKey()
	authWithOptions := []string{
		`# comments to ignore before any keys...`,
		``,
		`env="HOME=/home/root",no-port-forwarding ssh-rsa ` + pubSerialized + ` user@host`,
		`# comments to ignore, along with a blank line`,
		``,
		`env="HOME=/home/root2" ssh-rsa ` + pubSerialized + ` user2@host2`,
		``,
		`# more comments, plus a invalid entry`,
		`ssh-rsa data-that-will-not-parse user@host3`,
	}
	for _, eol := range []string{"\n", "\r\n"} {
		authOptions := strings.Join(authWithOptions, eol)
		rest2 := strings.Join(authWithOptions[3:], eol)
		rest3 := strings.Join(authWithOptions[6:], eol)
		testAuthorizedKeys(t, []byte(authOptions), []testAuthResult{
			{pub, []string{`env="HOME=/home/root"`, "no-port-forwarding"}, "user@host", rest2, true},
			{pub, []string{`env="HOME=/home/root2"`}, "user2@host2", rest3, true},
			{nil, nil, "", "", false},
		})
	}
}

func TestAuthWithQuotedSpaceInEnv(t *testing.T) {
	pub, pubSerialized := getTestKey()
	authWithQuotedSpaceInEnv := []byte(`env="HOME=/home/root dir",no-port-forwarding ssh-rsa ` + pubSerialized + ` user@host`)
	testAuthorizedKeys(t, []byte(authWithQuotedSpaceInEnv), []testAuthResult{
		{pub, []string{`env="HOME=/home/root dir"`, "no-port-forwarding"}, "user@host", "", true},
	})
}

func TestAuthWithQuotedCommaInEnv(t *testing.T) {
	pub, pubSerialized := getTestKey()
	authWithQuotedCommaInEnv := []byte(`env="HOME=/home/root,dir",no-port-forwarding ssh-rsa ` + pubSerialized + `   user@host`)
	testAuthorizedKeys(t, []byte(authWithQuotedCommaInEnv), []testAuthResult{
		{pub, []string{`env="HOME=/home/root,dir"`, "no-port-forwarding"}, "user@host", "", true},
	})
}

func TestAuthWithQuotedQuoteInEnv(t *testing.T) {
	pub, pubSerialized := getTestKey()
	authWithQuotedQuoteInEnv := []byte(`env="HOME=/home/\"root dir",no-port-forwarding` + "\t" + `ssh-rsa` + "\t" + pubSerialized + `   user@host`)
	authWithDoubleQuotedQuote := []byte(`no-port-forwarding,env="HOME=/home/ \"root dir\"" ssh-rsa ` + pubSerialized + "\t" + `user@host`)
	testAuthorizedKeys(t, []byte(authWithQuotedQuoteInEnv), []testAuthResult{
		{pub, []string{`env="HOME=/home/\"root dir"`, "no-port-forwarding"}, "user@host", "", true},
	})

	testAuthorizedKeys(t, []byte(authWithDoubleQuotedQuote), []testAuthResult{
		{pub, []string{"no-port-forwarding", `env="HOME=/home/ \"root dir\""`}, "user@host", "", true},
	})
}

func TestAuthWithInvalidSpace(t *testing.T) {
	_, pubSerialized := getTestKey()
	authWithInvalidSpace := []byte(`env="HOME=/home/root dir", no-port-forwarding ssh-rsa ` + pubSerialized + ` user@host
#more to follow but still no valid keys`)
	testAuthorizedKeys(t, []byte(authWithInvalidSpace), []testAuthResult{
		{nil, nil, "", "", false},
	})
}

func TestAuthWithMissingQuote(t *testing.T) {
	pub, pubSerialized := getTestKey()
	authWithMissingQuote := []byte(`env="HOME=/home/root,no-port-forwarding ssh-rsa ` + pubSerialized + ` user@host
env="HOME=/home/root",shared-control ssh-rsa ` + pubSerialized + ` user@host`)

	testAuthorizedKeys(t, []byte(authWithMissingQuote), []testAuthResult{
		{pub, []string{`env="HOME=/home/root"`, `shared-control`}, "user@host", "", true},
	})
}

func TestInvalidEntry(t *testing.T) {
	authInvalid := []byte(`ssh-rsa`)
	_, _, _, _, err := ParseAuthorizedKey(authInvalid)
	if err == nil {
		t.Errorf("got valid entry for %q", authInvalid)
	}
}

var knownHostsParseTests = []struct {
	input string
	err   string

	marker  string
	comment string
	hosts   []string
	rest    string
}{
	{
		"",
		"EOF",

		"", "", nil, "",
	},
	{
		"# Just a comment",
		"EOF",

		"", "", nil, "",
	},
	{
		"   \t   ",
		"EOF",

		"", "", nil, "",
	},
	{
		"localhost ssh-rsa {RSAPUB}",
		"",

		"", "", []string{"localhost"}, "",
	},
	{
		"localhost\tssh-rsa {RSAPUB}",
		"",

		"", "", []string{"localhost"}, "",
	},
	{
		"localhost\tssh-rsa {RSAPUB}\tcomment comment",
		"",

		"", "comment comment", []string{"localhost"}, "",
	},
	{
		"localhost\tssh-rsa {RSAPUB}\tcomment comment\n",
		"",

		"", "comment comment", []string{"localhost"}, "",
	},
	{
		"localhost\tssh-rsa {RSAPUB}\tcomment comment\r\n",
		"",

		"", "comment comment", []string{"localhost"}, "",
	},
	{
		"localhost\tssh-rsa {RSAPUB}\tcomment comment\r\nnext line",
		"",

		"", "comment comment", []string{"localhost"}, "next line",
	},
	{
		"localhost,[host2:123]\tssh-rsa {RSAPUB}\tcomment comment",
		"",

		"", "comment comment", []string{"localhost", "[host2:123]"}, "",
	},
	{
		"@marker \tlocalhost,[host2:123]\tssh-rsa {RSAPUB}",
		"",

		"marker", "", []string{"localhost", "[host2:123]"}, "",
	},
	{
		"@marker \tlocalhost,[host2:123]\tssh-rsa aabbccdd",
		"short read",

		"", "", nil, "",
	},
}

func TestKnownHostsParsing(t *testing.T) {
	rsaPub, rsaPubSerialized := getTestKey()

	for i, test := range knownHostsParseTests {
		var expectedKey PublicKey
		const rsaKeyToken = "{RSAPUB}"

		input := test.input
		if strings.Contains(input, rsaKeyToken) {
			expectedKey = rsaPub
			input = strings.Replace(test.input, rsaKeyToken, rsaPubSerialized, -1)
		}

		marker, hosts, pubKey, comment, rest, err := ParseKnownHosts([]byte(input))
		if err != nil {
			if len(test.err) == 0 {
				t.Errorf("#%d: unexpectedly failed with %q", i, err)
			} else if !strings.Contains(err.Error(), test.err) {
				t.Errorf("#%d: expected error containing %q, but got %q", i, test.err, err)
			}
			continue
		} else if len(test.err) != 0 {
			t.Errorf("#%d: succeeded but expected error including %q", i, test.err)
			continue
		}

		if !reflect.DeepEqual(expectedKey, pubKey) {
			t.Errorf("#%d: expected key %#v, but got %#v", i, expectedKey, pubKey)
		}

		if marker != test.marker {
			t.Errorf("#%d: expected marker %q, but got %q", i, test.marker, marker)
		}

		if comment != test.comment {
			t.Errorf("#%d: expected comment %q, but got %q", i, test.comment, comment)
		}

		if !reflect.DeepEqual(test.hosts, hosts) {
			t.Errorf("#%d: expected hosts %#v, but got %#v", i, test.hosts, hosts)
		}

		if rest := string(rest); rest != test.rest {
			t.Errorf("#%d: expected remaining input to be %q, but got %q", i, test.rest, rest)
		}
	}
}

func TestFingerprintLegacyMD5(t *testing.T) {
	pub, _ := getTestKey()
	fingerprint := FingerprintLegacyMD5(pub)
	want := "fb:61:6d:1a:e3:f0:95:45:3c:a0:79:be:4a:93:63:66" // ssh-keygen -lf -E md5 rsa
	if fingerprint != want {
		t.Errorf("got fingerprint %q want %q", fingerprint, want)
	}
}

func TestFingerprintSHA256(t *testing.T) {
	pub, _ := getTestKey()
	fingerprint := FingerprintSHA256(pub)
	want := "SHA256:Anr3LjZK8YVpjrxu79myrW9Hrb/wpcMNpVvTq/RcBm8" // ssh-keygen -lf rsa
	if fingerprint != want {
		t.Errorf("got fingerprint %q want %q", fingerprint, want)
	}
}

func TestInvalidKeys(t *testing.T) {
	keyTypes := []string{
		"RSA PRIVATE KEY",
		"PRIVATE KEY",
		"EC PRIVATE KEY",
		"DSA PRIVATE KEY",
		"OPENSSH PRIVATE KEY",
	}

	for _, keyType := range keyTypes {
		for _, dataLen := range []int{0, 1, 2, 5, 10, 20} {
			data := make([]byte, dataLen)
			if _, err := io.ReadFull(rand.Reader, data); err != nil {
				t.Fatal(err)
			}

			var buf bytes.Buffer
			pem.Encode(&buf, &pem.Block{
				Type:  keyType,
				Bytes: data,
			})

			// This test is just to ensure that the function
			// doesn't panic so the return value is ignored.
			ParseRawPrivateKey(buf.Bytes())
		}
	}
}

func TestSKKeys(t *testing.T) {
	for _, d := range testdata.SKData {
		pk, _, _, _, err := ParseAuthorizedKey(d.PubKey)
		if err != nil {
			t.Fatalf("parseAuthorizedKey returned error: %v", err)
		}

		sigBuf := make([]byte, hex.DecodedLen(len(d.HexSignature)))
		if _, err := hex.Decode(sigBuf, d.HexSignature); err != nil {
			t.Fatalf("hex.Decode() failed: %v", err)
		}

		dataBuf := make([]byte, hex.DecodedLen(len(d.HexData)))
		if _, err := hex.Decode(dataBuf, d.HexData); err != nil {
			t.Fatalf("hex.Decode() failed: %v", err)
		}

		sig, _, ok := parseSignature(sigBuf)
		if !ok {
			t.Fatalf("parseSignature(%v) failed", sigBuf)
		}

		// Test that good data and signature pass verification
		if err := pk.Verify(dataBuf, sig); err != nil {
			t.Errorf("%s: PublicKey.Verify(%v, %v) failed: %v", d.Name, dataBuf, sig, err)
		}

		// Invalid data being passed in
		invalidData := []byte("INVALID DATA")
		if err := pk.Verify(invalidData, sig); err == nil {
			t.Errorf("%s with invalid data: PublicKey.Verify(%v, %v) passed unexpectedly", d.Name, invalidData, sig)
		}

		// Change byte in blob to corrup signature
		sig.Blob[5] = byte('A')
		// Corrupted data being passed in
		if err := pk.Verify(dataBuf, sig); err == nil {
			t.Errorf("%s with corrupted signature: PublicKey.Verify(%v, %v) passed unexpectedly", d.Name, dataBuf, sig)
		}
	}
}

// TestLargeEPublicKeyParse verifies that RSA public keys with exponents larger
// than 24 bits are parsed successfully instead of returning "exponent too large".
func TestLargeEPublicKeyParse(t *testing.T) {
	// 33-bit exponent: previously rejected with "ssh: exponent too large".
	largeE := new(big.Int).SetUint64(1<<32 + 1)
	// Arbitrary 2048-bit modulus sufficient for parse/marshal testing.
	nBytes := make([]byte, 256)
	nBytes[0] = 0x01
	for i := 1; i < len(nBytes); i++ {
		nBytes[i] = byte(i)
	}
	n := new(big.Int).SetBytes(nBytes)

	// Build the SSH wire-format public key blob (algorithm name + E + N).
	wireKey := struct {
		Name string
		E    *big.Int
		N    *big.Int
	}{"ssh-rsa", largeE, n}
	rawBytes := Marshal(&wireKey)

	pub, err := ParsePublicKey(rawBytes)
	if err != nil {
		t.Fatalf("ParsePublicKey with 33-bit E: %v", err)
	}
	largeKey, ok := pub.(*rsaLargeEPublicKey)
	if !ok {
		t.Fatalf("expected *rsaLargeEPublicKey, got %T", pub)
	}
	if largeKey.E.Cmp(largeE) != 0 {
		t.Errorf("exponent: got %v, want %v", largeKey.E, largeE)
	}
	if largeKey.N.Cmp(n) != 0 {
		t.Errorf("modulus mismatch")
	}

	// Marshal → ParsePublicKey roundtrip must be stable.
	pub2, err := ParsePublicKey(pub.Marshal())
	if err != nil {
		t.Fatalf("roundtrip ParsePublicKey: %v", err)
	}
	if _, ok := pub2.(*rsaLargeEPublicKey); !ok {
		t.Errorf("roundtrip: expected *rsaLargeEPublicKey, got %T", pub2)
	}

	// JSON must include an "exponent" field with the large value.
	jsonBytes, err := json.Marshal(pub)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if !bytes.Contains(jsonBytes, []byte(`"exponent"`)) {
		t.Errorf("JSON output missing 'exponent': %s", jsonBytes)
	}
}

// TestLargeEPublicKeyVerify exercises the custom PKCS#1 v1.5 verification
// logic (verifyRSAPKCS1v15LargeE) with both small (≤ 24-bit) and large
// (33-bit) exponents, across all three SSH RSA signature algorithms, and with
// both correct and tampered signatures.
//
// The small-E cases prove that our verifier agrees with the standard library
// behaviour; the large-E cases prove that the new code path works end-to-end.
func TestLargeEPublicKeyVerify(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyLen := (priv.N.BitLen() + 7) / 8

	// computeD derives the private exponent for a given public exponent e using
	// the same modulus as priv.  Returns (d, true) on success or (nil, false)
	// if e is not coprime to lambda(n) (astronomically unlikely for prime e).
	computeD := func(e *big.Int) (*big.Int, bool) {
		pm1 := new(big.Int).Sub(priv.Primes[0], big.NewInt(1))
		qm1 := new(big.Int).Sub(priv.Primes[1], big.NewInt(1))
		g := new(big.Int).GCD(nil, nil, pm1, qm1)
		lambda := new(big.Int).Div(new(big.Int).Mul(pm1, qm1), g)
		d := new(big.Int).ModInverse(e, lambda)
		return d, d != nil
	}

	// makeSignature builds a well-formed PKCS#1 v1.5 signature over data using
	// private exponent d and the hash algorithm implied by alg.
	makeSignature := func(d *big.Int, data []byte, alg string) *Signature {
		hash := hashFuncs[alg]
		h := hash.New()
		h.Write(data)
		digest := h.Sum(nil)

		prefix := pkcs1v15DigestPrefixes[hash]
		psLen := keyLen - 3 - len(prefix) - len(digest)
		if psLen < 8 {
			t.Fatalf("key too small for %s padding (psLen=%d)", alg, psLen)
		}

		// EM = 0x00 || 0x01 || PS(0xff × psLen) || 0x00 || DigestInfo || hash
		em := make([]byte, keyLen)
		em[1] = 0x01
		for i := 2; i < 2+psLen; i++ {
			em[i] = 0xff
		}
		em[2+psLen] = 0x00
		copy(em[3+psLen:], prefix)
		copy(em[3+psLen+len(prefix):], digest)

		// s = EM^d mod n
		m := new(big.Int).SetBytes(em)
		s := new(big.Int).Exp(m, d, priv.N)
		sigBytes := make([]byte, keyLen)
		sb := s.Bytes()
		copy(sigBytes[keyLen-len(sb):], sb)
		return &Signature{Format: alg, Blob: sigBytes}
	}

	// Small E: 65537 (17 bits, well within the 24-bit limit).
	// rsa.GenerateKey guarantees gcd(65537, phi(n)) = 1, so ModInverse always succeeds.
	smallE := big.NewInt(65537)
	smallD, ok := computeD(smallE)
	if !ok {
		t.Fatal("65537 not coprime to lambda(n); this should never happen with rsa.GenerateKey")
	}
	smallPub := &rsaLargeEPublicKey{N: priv.N, E: smallE}

	// Large E: random 33-bit prime (exceeds the former 24-bit rejection threshold).
	// A prime E is coprime to (p-1)(q-1) unless p or q equals E — impossible for
	// a 33-bit prime and 2048-bit primes.
	largeE, err := rand.Prime(rand.Reader, 33)
	if err != nil {
		t.Fatalf("generate 33-bit prime E: %v", err)
	}
	largeD, ok := computeD(largeE)
	if !ok {
		t.Skip("largeE not coprime to lambda(n); should be impossible for a prime E with 2048-bit primes")
	}
	largePub := &rsaLargeEPublicKey{N: priv.N, E: largeE}

	data := []byte("zgrab2 large-E RSA test message")

	tests := []struct {
		name    string
		pub     *rsaLargeEPublicKey
		d       *big.Int
		alg     string
		tamper  bool // flip bits in the signature to make it invalid
		wantErr bool
	}{
		// ── small E (≤ 24-bit) ───────────────────────────────────────────────────────────────────────────────────────
		// These cases validate that our custom verifier agrees with the standard
		// library for ordinary exponents.
		{"small-E/ssh-rsa/good", smallPub, smallD, KeyAlgoRSA, false, false},
		{"small-E/ssh-rsa/bad", smallPub, smallD, KeyAlgoRSA, true, true},
		{"small-E/rsa-sha2-256/good", smallPub, smallD, KeyAlgoRSASHA256, false, false},
		{"small-E/rsa-sha2-256/bad", smallPub, smallD, KeyAlgoRSASHA256, true, true},
		{"small-E/rsa-sha2-512/good", smallPub, smallD, KeyAlgoRSASHA512, false, false},
		{"small-E/rsa-sha2-512/bad", smallPub, smallD, KeyAlgoRSASHA512, true, true},

		// ── large E (> 24-bit, not allowed in std lib, so we use our custom implementation) ──────────────────────────
		{"large-E/ssh-rsa/good", largePub, largeD, KeyAlgoRSA, false, false},
		{"large-E/ssh-rsa/bad", largePub, largeD, KeyAlgoRSA, true, true},
		{"large-E/rsa-sha2-256/good", largePub, largeD, KeyAlgoRSASHA256, false, false},
		{"large-E/rsa-sha2-256/bad", largePub, largeD, KeyAlgoRSASHA256, true, true},
		{"large-E/rsa-sha2-512/good", largePub, largeD, KeyAlgoRSASHA512, false, false},
		{"large-E/rsa-sha2-512/bad", largePub, largeD, KeyAlgoRSASHA512, true, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sig := makeSignature(tc.d, data, tc.alg)
			if tc.tamper {
				// Flip several bits spread across the signature blob so that no
				// single lucky cancellation can cause a false pass.
				sig.Blob[10] ^= 0xff
				sig.Blob[keyLen/2] ^= 0x55
			}
			err := tc.pub.Verify(data, sig)
			if tc.wantErr && err == nil {
				t.Error("expected verification error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected verification error: %v", err)
			}
		})
	}

	// Cross-key rejection: a signature made with the small-E key must not
	// verify under the large-E key (different private exponents, same modulus).
	t.Run("cross-key-rejection", func(t *testing.T) {
		sig := makeSignature(smallD, data, KeyAlgoRSASHA256)
		if err := largePub.Verify(data, sig); err == nil {
			t.Error("signature from small-E key should not verify under large-E key")
		}
	})

	// Wrong-format rejection: passing an unsupported signature format must fail
	// before any cryptographic operation.
	t.Run("wrong-format-rejection", func(t *testing.T) {
		sig := makeSignature(largeD, data, KeyAlgoRSASHA256)
		sig.Format = "ssh-dss" // wrong algorithm entirely
		if err := largePub.Verify(data, sig); err == nil {
			t.Error("wrong signature format should be rejected")
		}
	})

	// Small-E agreement: verify that our custom verifier gives the same result
	// as rsa.VerifyPKCS1v15 for a standard 65537 key.
	stdPriv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: priv.N, E: 65537},
		D:         smallD,
		Primes:    priv.Primes,
	}
	checkAgreement := func(t *testing.T, sig *Signature) {
		t.Helper()
		digest := func() []byte {
			h := hashFuncs[KeyAlgoRSASHA256].New()
			h.Write(data)
			return h.Sum(nil)
		}()
		stdErr := rsa.VerifyPKCS1v15(&stdPriv.PublicKey, hashFuncs[KeyAlgoRSASHA256], digest, sig.Blob)
		ourErr := smallPub.Verify(data, sig)
		if (stdErr == nil) != (ourErr == nil) {
			t.Errorf("stdlib says %v but our verifier says %v", stdErr, ourErr)
		}
	}
	t.Run("small-E-agrees-with-stdlib/valid", func(t *testing.T) {
		sig := makeSignature(smallD, data, KeyAlgoRSASHA256)
		checkAgreement(t, sig)
	})
	t.Run("small-E-agrees-with-stdlib/tampered", func(t *testing.T) {
		sig := makeSignature(smallD, data, KeyAlgoRSASHA256)
		sig.Blob[10] ^= 0xff
		sig.Blob[len(sig.Blob)/2] ^= 0x55
		checkAgreement(t, sig)
	})
}

