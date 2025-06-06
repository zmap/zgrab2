// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"

	ztoolsKeys "github.com/zmap/zgrab2/tools/keys"

	"golang.org/x/crypto/curve25519"
)

const (
	kexAlgoDH1SHA1                = "diffie-hellman-group1-sha1"
	kexAlgoDH14SHA1               = "diffie-hellman-group14-sha1"
	kexAlgoDH14SHA256             = "diffie-hellman-group14-sha256"
	kexAlgoECDH256                = "ecdh-sha2-nistp256"
	kexAlgoECDH384                = "ecdh-sha2-nistp384"
	kexAlgoECDH521                = "ecdh-sha2-nistp521"
	kexAlgoCurve25519SHA256LibSSH = "curve25519-sha256@libssh.org"
	kexAlgoCurve25519SHA256       = "curve25519-sha256"

	// For the following kex only the client half contains a production
	// ready implementation. The server half only consists of a minimal
	// implementation to satisfy the automated tests.
	kexAlgoDHGEXSHA1   = "diffie-hellman-group-exchange-sha1"
	kexAlgoDHGEXSHA256 = "diffie-hellman-group-exchange-sha256"
)

// kexResult captures the outcome of a key exchange.
type kexResult struct {
	// Session hash. See also RFC 4253, section 8.
	H []byte `json:"H,omitempty"`

	// Shared secret. See also RFC 4253, section 8.
	K []byte `json:"K,omitempty"`

	// Host key as hashed into H.
	HostKey []byte `json:"-"`

	// Signature of H.
	Signature []byte `json:"-"`

	// A cryptographic hash function that matches the security
	// level of the key exchange algorithm. It is used for
	// calculating H, and for deriving keys from H and K.
	Hash crypto.Hash `json:"-"`

	// The session ID, which is the first H computed. This is used
	// to derive key material inside the transport.
	SessionID []byte `json:"session_id,omitempty"`
}

// handshakeMagics contains data that is always included in the
// session hash.
type handshakeMagics struct {
	clientVersion, serverVersion []byte
	clientKexInit, serverKexInit []byte
}

func (m *handshakeMagics) write(w io.Writer) {
	writeString(w, m.clientVersion)
	writeString(w, m.serverVersion)
	writeString(w, m.clientKexInit)
	writeString(w, m.serverKexInit)
}

type PublicKeyJsonLog struct {
	RSAHostKey     *PublicKey `json:"rsa_public_key,omitempty"`
	DSAHostKey     *PublicKey `json:"dsa_public_key,omitempty"`
	ECDSAHostKey   *PublicKey `json:"ecdsa_public_key,omitempty"`
	Ed25519HostKey *PublicKey `json:"ed25519_public_key,omitempty"`
	CertKeyHostKey *PublicKey `json:"certkey_public_key,omitempty"`
}

func (pkLog *PublicKeyJsonLog) AddPublicKey(pubKey PublicKey) bool {
	switch pubKey.Type() {
	case KeyAlgoRSA:
		pkLog.RSAHostKey = &pubKey
		return true

	case KeyAlgoDSA:
		pkLog.DSAHostKey = &pubKey
		return true

	case KeyAlgoECDSA256, KeyAlgoECDSA384, KeyAlgoECDSA521:
		pkLog.ECDSAHostKey = &pubKey
		return true

	case KeyAlgoED25519:
		pkLog.Ed25519HostKey = &pubKey
		return true

	case CertAlgoRSAv01, CertAlgoDSAv01, CertAlgoECDSA256v01, CertAlgoECDSA384v01, CertAlgoECDSA521v01, CertAlgoED25519v01, CertAlgoSKECDSA256v01, CertAlgoSKED25519v01:
		pkLog.CertKeyHostKey = &pubKey
		return true

	default:
		return false
	}
}

type ServerHostKeyJsonLog struct {
	PublicKeyJsonLog
	Raw          []byte `json:"raw"`
	Algorithm    string `json:"algorithm"`
	Fingerprint  string `json:"fingerprint_sha256,omitempty"`
	TrailingData []byte `json:"trailing_data,omitempty"`
	ParseError   string `json:"parse_error,omitempty"`
}

func LogServerHostKey(sshRawKey []byte) *ServerHostKeyJsonLog {
	ret := new(ServerHostKeyJsonLog)
	ret.Raw = sshRawKey
	tempHash := sha256.Sum256(sshRawKey)
	ret.Fingerprint = hex.EncodeToString(tempHash[:])

	keyAlgorithm, keyBytes, ok := parseString(sshRawKey)
	if !ok {
		ret.Algorithm = "unknown"
		return ret
	}
	ret.Algorithm = string(keyAlgorithm)

	keyObj, rest, err := parsePubKey(keyBytes, ret.Algorithm)
	if err != nil {
		ret.ParseError = err.Error()
		return ret
	}
	ret.TrailingData = rest

	ok = ret.PublicKeyJsonLog.AddPublicKey(keyObj)
	if !ok {
		ret.ParseError = "Cannot parse to JSON"
	}

	return ret
}

// kexAlgorithm abstracts different key exchange algorithms.
type kexAlgorithm interface {
	// Server runs server-side key agreement, signing the result
	// with a hostkey. algo is the negotiated algorithm, and may
	// be a certificate type.
	Server(p packetConn, rand io.Reader, magics *handshakeMagics, s AlgorithmSigner, algo string, c *Config) (*kexResult, error)

	// Client runs the client-side key agreement. Caller is
	// responsible for verifying the host key signature.
	Client(p packetConn, rand io.Reader, magics *handshakeMagics, c *Config) (*kexResult, error)

	// Create a JSON object for the kexAlgorithm group
	MarshalJSON() ([]byte, error)

	// Get a new instance of this interface
	// Because the base x/crypto package passes the same object to each connection
	GetNew(keyType string) kexAlgorithm
}

// dhGroup is a multiplicative group suitable for implementing Diffie-Hellman key agreement.
type dhGroup struct {
	g, p, pMinus1 *big.Int
	hashFunc      crypto.Hash
	JsonLog       dhGroupJsonLog
}
type dhGroupJsonLog struct {
	Parameters      *ztoolsKeys.DHParams  `json:"dh_params,omitempty"`
	ServerSignature *JsonSignature        `json:"server_signature,omitempty"`
	ServerHostKey   *ServerHostKeyJsonLog `json:"server_host_key,omitempty"`
}

func (group *dhGroup) MarshalJSON() ([]byte, error) {
	group.JsonLog.Parameters.Generator = group.g
	group.JsonLog.Parameters.Prime = group.p
	return json.Marshal(group.JsonLog)
}

func (group *dhGroup) GetNew(keyType string) kexAlgorithm {
	ret := new(dhGroup)
	ret.g = new(big.Int).SetInt64(2)

	switch keyType {
	case kexAlgoDH1SHA1:
		ret.p, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16)
		ret.pMinus1 = new(big.Int).Sub(ret.p, bigOne)
		ret.hashFunc = crypto.SHA1
		break

	case kexAlgoDH14SHA1:
		ret.p, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
		ret.pMinus1 = new(big.Int).Sub(ret.p, bigOne)
		ret.hashFunc = crypto.SHA1
		break

	case kexAlgoDH14SHA256:
		ret.p, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
		ret.pMinus1 = new(big.Int).Sub(ret.p, bigOne)
		ret.hashFunc = crypto.SHA256
		break

	default:
		panic("Unimplemented DH KEX selected")
	}

	return ret
}

func (group *dhGroup) diffieHellman(theirPublic, myPrivate *big.Int) (*big.Int, error) {
	if theirPublic.Cmp(bigOne) <= 0 || theirPublic.Cmp(group.pMinus1) >= 0 {
		return nil, errors.New("ssh: DH parameter out of bounds")
	}
	return new(big.Int).Exp(theirPublic, myPrivate, group.p), nil
}

func (group *dhGroup) Client(c packetConn, randSource io.Reader, magics *handshakeMagics, config *Config) (*kexResult, error) {
	group.JsonLog.Parameters = new(ztoolsKeys.DHParams)

	var x *big.Int
	for {
		var err error
		if x, err = rand.Int(randSource, group.pMinus1); err != nil {
			return nil, err
		}
		if x.Sign() > 0 {
			break
		}
	}

	if config.Verbose {
		group.JsonLog.Parameters.ClientPrivate = x
	}

	X := new(big.Int).Exp(group.g, x, group.p)

	if config.Verbose {
		group.JsonLog.Parameters.ClientPublic = X
	}

	kexDHInit := kexDHInitMsg{
		X: X,
	}
	if err := c.writePacket(Marshal(&kexDHInit)); err != nil {
		return nil, err
	}

	packet, err := c.readPacket()
	if err != nil {
		return nil, err
	}

	var kexDHReply kexDHReplyMsg
	if err = Unmarshal(packet, &kexDHReply); err != nil {
		return nil, err
	}

	group.JsonLog.Parameters.ServerPublic = kexDHReply.Y
	group.JsonLog.ServerSignature = new(JsonSignature)
	group.JsonLog.ServerSignature.Raw = kexDHReply.Signature
	group.JsonLog.ServerSignature.Parsed, _, _ = parseSignatureBody(kexDHReply.Signature)
	group.JsonLog.ServerHostKey = LogServerHostKey(kexDHReply.HostKey)

	ki, err := group.diffieHellman(kexDHReply.Y, x)
	if err != nil {
		return nil, err
	}

	h := group.hashFunc.New()
	magics.write(h)
	writeString(h, kexDHReply.HostKey)
	writeInt(h, X)
	writeInt(h, kexDHReply.Y)
	K := make([]byte, intLength(ki))
	marshalInt(K, ki)
	h.Write(K)
	H := h.Sum(nil)
	group.JsonLog.ServerSignature.H = H

	return &kexResult{
		H:         H,
		K:         K,
		HostKey:   kexDHReply.HostKey,
		Signature: kexDHReply.Signature,
		Hash:      group.hashFunc,
	}, nil
}

func (group *dhGroup) Server(c packetConn, randSource io.Reader, magics *handshakeMagics, priv AlgorithmSigner, algo string, config *Config) (result *kexResult, err error) {
	packet, err := c.readPacket()
	if err != nil {
		return
	}
	var kexDHInit kexDHInitMsg
	if err = Unmarshal(packet, &kexDHInit); err != nil {
		return
	}

	var y *big.Int
	for {
		if y, err = rand.Int(randSource, group.pMinus1); err != nil {
			return
		}
		if y.Sign() > 0 {
			break
		}
	}

	Y := new(big.Int).Exp(group.g, y, group.p)
	ki, err := group.diffieHellman(kexDHInit.X, y)
	if err != nil {
		return nil, err
	}

	hostKeyBytes := priv.PublicKey().Marshal()

	h := group.hashFunc.New()
	magics.write(h)
	writeString(h, hostKeyBytes)
	writeInt(h, kexDHInit.X)
	writeInt(h, Y)

	K := make([]byte, intLength(ki))
	marshalInt(K, ki)
	h.Write(K)

	H := h.Sum(nil)

	// H is already a hash, but the hostkey signing will apply its
	// own key-specific hash algorithm.
	sig, err := signAndMarshal(priv, randSource, H, algo)
	if err != nil {
		return nil, err
	}

	kexDHReply := kexDHReplyMsg{
		HostKey:   hostKeyBytes,
		Y:         Y,
		Signature: sig,
	}
	packet = Marshal(&kexDHReply)

	err = c.writePacket(packet)
	return &kexResult{
		H:         H,
		K:         K,
		HostKey:   hostKeyBytes,
		Signature: sig,
		Hash:      group.hashFunc,
	}, err
}

// ecdh performs Elliptic Curve Diffie-Hellman key exchange as
// described in RFC 5656, section 4.
type ecdh struct {
	curve   elliptic.Curve
	JsonLog ecdhJsonLog
}

type ecdhJsonLog struct {
	Parameters      *ztoolsKeys.ECDHParams `json:"ecdh_params,omitempty"`
	ServerSignature *JsonSignature         `json:"server_signature,omitempty"`
	ServerHostKey   *ServerHostKeyJsonLog  `json:"server_host_key,omitempty"`
}

func (kex *ecdh) MarshalJSON() ([]byte, error) {
	return json.Marshal(kex.JsonLog)
}

func (kex *ecdh) GetNew(keyType string) kexAlgorithm {
	ret := new(ecdh)

	switch keyType {
	case kexAlgoECDH521:
		ret.curve = elliptic.P521()
		break

	case kexAlgoECDH384:
		ret.curve = elliptic.P384()
		break

	case kexAlgoECDH256:
		ret.curve = elliptic.P256()
		break

	default:
		panic("Unimplemented ECDH KEX selected")
	}

	return ret
}

func (kex *ecdh) Client(c packetConn, rand io.Reader, magics *handshakeMagics, config *Config) (*kexResult, error) {
	ephKey, err := ecdsa.GenerateKey(kex.curve, rand)
	if err != nil {
		return nil, err
	}

	kex.JsonLog.Parameters = new(ztoolsKeys.ECDHParams)

	if config.Verbose {
		if ephKey.PublicKey.X != nil || ephKey.PublicKey.Y != nil {
			kex.JsonLog.Parameters.ClientPublic = new(ztoolsKeys.ECPoint)
			kex.JsonLog.Parameters.ClientPublic.X = ephKey.PublicKey.X
			kex.JsonLog.Parameters.ClientPublic.Y = ephKey.PublicKey.Y
		}
		if ephKey.D != nil {
			kex.JsonLog.Parameters.ClientPrivate = new(ztoolsKeys.ECDHPrivateParams)
			kex.JsonLog.Parameters.ClientPrivate.Value = ephKey.D.Bytes()
			kex.JsonLog.Parameters.ClientPrivate.Length = ephKey.D.BitLen()
		}
	}

	kexInit := kexECDHInitMsg{
		ClientPubKey: elliptic.Marshal(kex.curve, ephKey.PublicKey.X, ephKey.PublicKey.Y),
	}

	serialized := Marshal(&kexInit)
	if err := c.writePacket(serialized); err != nil {
		return nil, err
	}

	packet, err := c.readPacket()
	if err != nil {
		return nil, err
	}

	var reply kexECDHReplyMsg
	if err = Unmarshal(packet, &reply); err != nil {
		return nil, err
	}

	x, y, err := unmarshalECKey(kex.curve, reply.EphemeralPubKey)
	if x != nil || y != nil {
		kex.JsonLog.Parameters.ServerPublic = new(ztoolsKeys.ECPoint)
		kex.JsonLog.Parameters.ServerPublic.X = x
		kex.JsonLog.Parameters.ServerPublic.Y = y
	}
	kex.JsonLog.ServerHostKey = LogServerHostKey(reply.HostKey)
	kex.JsonLog.ServerSignature = new(JsonSignature)
	kex.JsonLog.ServerSignature.Raw = reply.Signature
	kex.JsonLog.ServerSignature.Parsed, _, _ = parseSignatureBody(reply.Signature)
	if err != nil {
		return nil, err
	}

	// generate shared secret
	secret, _ := kex.curve.ScalarMult(x, y, ephKey.D.Bytes())

	h := ecHash(kex.curve).New()
	magics.write(h)
	writeString(h, reply.HostKey)
	writeString(h, kexInit.ClientPubKey)
	writeString(h, reply.EphemeralPubKey)
	K := make([]byte, intLength(secret))
	marshalInt(K, secret)
	h.Write(K)
	H := h.Sum(nil)
	kex.JsonLog.ServerSignature.H = H

	return &kexResult{
		H:         H,
		K:         K,
		HostKey:   reply.HostKey,
		Signature: reply.Signature,
		Hash:      ecHash(kex.curve),
	}, nil
}

// unmarshalECKey parses and checks an EC key.
func unmarshalECKey(curve elliptic.Curve, pubkey []byte) (x, y *big.Int, err error) {
	x, y = elliptic.Unmarshal(curve, pubkey)
	if x == nil {
		return nil, nil, errors.New("ssh: elliptic.Unmarshal failure")
	}
	if !validateECPublicKey(curve, x, y) {
		return nil, nil, errors.New("ssh: public key not on curve")
	}
	return x, y, nil
}

// validateECPublicKey checks that the point is a valid public key for
// the given curve. See [SEC1], 3.2.2
func validateECPublicKey(curve elliptic.Curve, x, y *big.Int) bool {
	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}

	if x.Cmp(curve.Params().P) >= 0 {
		return false
	}

	if y.Cmp(curve.Params().P) >= 0 {
		return false
	}

	if !curve.IsOnCurve(x, y) {
		return false
	}

	// We don't check if N * PubKey == 0, since
	//
	// - the NIST curves have cofactor = 1, so this is implicit.
	// (We don't foresee an implementation that supports non NIST
	// curves)
	//
	// - for ephemeral keys, we don't need to worry about small
	// subgroup attacks.
	return true
}

func (kex *ecdh) Server(c packetConn, rand io.Reader, magics *handshakeMagics, priv AlgorithmSigner, algo string, config *Config) (result *kexResult, err error) {
	packet, err := c.readPacket()
	if err != nil {
		return nil, err
	}

	var kexECDHInit kexECDHInitMsg
	if err = Unmarshal(packet, &kexECDHInit); err != nil {
		return nil, err
	}

	clientX, clientY, err := unmarshalECKey(kex.curve, kexECDHInit.ClientPubKey)
	if err != nil {
		return nil, err
	}

	// We could cache this key across multiple users/multiple
	// connection attempts, but the benefit is small. OpenSSH
	// generates a new key for each incoming connection.
	ephKey, err := ecdsa.GenerateKey(kex.curve, rand)
	if err != nil {
		return nil, err
	}

	hostKeyBytes := priv.PublicKey().Marshal()

	serializedEphKey := elliptic.Marshal(kex.curve, ephKey.PublicKey.X, ephKey.PublicKey.Y)

	// generate shared secret
	secret, _ := kex.curve.ScalarMult(clientX, clientY, ephKey.D.Bytes())

	h := ecHash(kex.curve).New()
	magics.write(h)
	writeString(h, hostKeyBytes)
	writeString(h, kexECDHInit.ClientPubKey)
	writeString(h, serializedEphKey)

	K := make([]byte, intLength(secret))
	marshalInt(K, secret)
	h.Write(K)

	H := h.Sum(nil)

	// H is already a hash, but the hostkey signing will apply its
	// own key-specific hash algorithm.
	sig, err := signAndMarshal(priv, rand, H, algo)
	if err != nil {
		return nil, err
	}

	reply := kexECDHReplyMsg{
		EphemeralPubKey: serializedEphKey,
		HostKey:         hostKeyBytes,
		Signature:       sig,
	}

	serialized := Marshal(&reply)
	if err := c.writePacket(serialized); err != nil {
		return nil, err
	}

	return &kexResult{
		H:         H,
		K:         K,
		HostKey:   reply.HostKey,
		Signature: sig,
		Hash:      ecHash(kex.curve),
	}, nil
}

// ecHash returns the hash to match the given elliptic curve, see RFC
// 5656, section 6.2.1
func ecHash(curve elliptic.Curve) crypto.Hash {
	bitSize := curve.Params().BitSize
	switch {
	case bitSize <= 256:
		return crypto.SHA256
	case bitSize <= 384:
		return crypto.SHA384
	}
	return crypto.SHA512
}

var kexAlgoMap = map[string]kexAlgorithm{}

func init() {
	// This is the group called diffie-hellman-group1-sha1 in
	// RFC 4253 and Oakley Group 2 in RFC 2409.
	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16)
	kexAlgoMap[kexAlgoDH1SHA1] = &dhGroup{
		g:        new(big.Int).SetInt64(2),
		p:        p,
		pMinus1:  new(big.Int).Sub(p, bigOne),
		hashFunc: crypto.SHA1,
	}

	// This are the groups called diffie-hellman-group14-sha1 and
	// diffie-hellman-group14-sha256 in RFC 4253 and RFC 8268,
	// and Oakley Group 14 in RFC 3526.
	p, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
	group14 := &dhGroup{
		g:       new(big.Int).SetInt64(2),
		p:       p,
		pMinus1: new(big.Int).Sub(p, bigOne),
	}

	kexAlgoMap[kexAlgoDH14SHA1] = &dhGroup{
		g: group14.g, p: group14.p, pMinus1: group14.pMinus1,
		hashFunc: crypto.SHA1,
	}
	kexAlgoMap[kexAlgoDH14SHA256] = &dhGroup{
		g: group14.g, p: group14.p, pMinus1: group14.pMinus1,
		hashFunc: crypto.SHA256,
	}

	kexAlgoMap[kexAlgoECDH521] = &ecdh{curve: elliptic.P521()}
	kexAlgoMap[kexAlgoECDH384] = &ecdh{curve: elliptic.P384()}
	kexAlgoMap[kexAlgoECDH256] = &ecdh{curve: elliptic.P256()}
	kexAlgoMap[kexAlgoCurve25519SHA256] = &curve25519sha256{}
	kexAlgoMap[kexAlgoCurve25519SHA256LibSSH] = &curve25519sha256{}
	kexAlgoMap[kexAlgoDHGEXSHA1] = &dhGEXSHA{hashFunc: crypto.SHA1}
	kexAlgoMap[kexAlgoDHGEXSHA256] = &dhGEXSHA{hashFunc: crypto.SHA256}
}

// curve25519sha256 implements the curve25519-sha256 (formerly known as
// curve25519-sha256@libssh.org) key exchange method, as described in RFC 8731.
type curve25519sha256 struct {
	JsonLog curve25519sha256JsonLog
}

type curve25519sha256JsonLog struct {
	Parameters      curve25519sha256JsonLogParameters `json:"curve25519_sha256_params"`
	ServerSignature *JsonSignature                    `json:"server_signature,omitempty"`
	ServerHostKey   *ServerHostKeyJsonLog             `json:"server_host_key,omitempty"`
}

type curve25519sha256JsonLogParameters struct {
	ClientPublic  []byte `json:"client_public,omitempty"`
	ClientPrivate []byte `json:"client_private,omitempty"`
	ServerPublic  []byte `json:"server_public,omitempty"`
}

func (kex *curve25519sha256) MarshalJSON() ([]byte, error) {
	return json.Marshal(kex.JsonLog)
}

func (kex *curve25519sha256) GetNew(keyType string) kexAlgorithm {
	return new(curve25519sha256)
}

type curve25519KeyPair struct {
	priv [32]byte
	pub  [32]byte
}

func (kp *curve25519KeyPair) generate(rand io.Reader) error {
	if _, err := io.ReadFull(rand, kp.priv[:]); err != nil {
		return err
	}
	curve25519.ScalarBaseMult(&kp.pub, &kp.priv)
	return nil
}

// curve25519Zeros is just an array of 32 zero bytes so that we have something
// convenient to compare against in order to reject curve25519 points with the
// wrong order.
var curve25519Zeros [32]byte

func (kex *curve25519sha256) Client(c packetConn, rand io.Reader, magics *handshakeMagics, config *Config) (*kexResult, error) {
	var kp curve25519KeyPair
	if err := kp.generate(rand); err != nil {
		return nil, err
	}

	if config.Verbose {
		kex.JsonLog.Parameters.ClientPublic = kp.pub[:]
		kex.JsonLog.Parameters.ClientPrivate = kp.priv[:]
	}

	if err := c.writePacket(Marshal(&kexECDHInitMsg{kp.pub[:]})); err != nil {
		return nil, err
	}

	packet, err := c.readPacket()
	if err != nil {
		return nil, err
	}

	var reply kexECDHReplyMsg
	if err = Unmarshal(packet, &reply); err != nil {
		return nil, err
	}

	kex.JsonLog.Parameters.ServerPublic = reply.EphemeralPubKey
	kex.JsonLog.ServerHostKey = LogServerHostKey(reply.HostKey)
	kex.JsonLog.ServerSignature = new(JsonSignature)
	kex.JsonLog.ServerSignature.Raw = reply.Signature
	kex.JsonLog.ServerSignature.Parsed, _, _ = parseSignatureBody(reply.Signature)
	if len(reply.EphemeralPubKey) != 32 {
		return nil, errors.New("ssh: peer's curve25519 public value has wrong length")
	}

	var servPub, secret [32]byte
	copy(servPub[:], reply.EphemeralPubKey)
	curve25519.ScalarMult(&secret, &kp.priv, &servPub)
	if subtle.ConstantTimeCompare(secret[:], curve25519Zeros[:]) == 1 {
		return nil, errors.New("ssh: peer's curve25519 public value has wrong order")
	}

	h := crypto.SHA256.New()
	magics.write(h)
	writeString(h, reply.HostKey)
	writeString(h, kp.pub[:])
	writeString(h, reply.EphemeralPubKey)

	ki := new(big.Int).SetBytes(secret[:])
	K := make([]byte, intLength(ki))
	marshalInt(K, ki)
	h.Write(K)
	H := h.Sum(nil)
	kex.JsonLog.ServerSignature.H = H

	return &kexResult{
		H:         H,
		K:         K,
		HostKey:   reply.HostKey,
		Signature: reply.Signature,
		Hash:      crypto.SHA256,
	}, nil
}

func (kex *curve25519sha256) Server(c packetConn, rand io.Reader, magics *handshakeMagics, priv AlgorithmSigner, algo string, config *Config) (result *kexResult, err error) {
	packet, err := c.readPacket()
	if err != nil {
		return
	}
	var kexInit kexECDHInitMsg
	if err = Unmarshal(packet, &kexInit); err != nil {
		return
	}

	if len(kexInit.ClientPubKey) != 32 {
		return nil, errors.New("ssh: peer's curve25519 public value has wrong length")
	}

	var kp curve25519KeyPair
	if err := kp.generate(rand); err != nil {
		return nil, err
	}

	var clientPub, secret [32]byte
	copy(clientPub[:], kexInit.ClientPubKey)
	curve25519.ScalarMult(&secret, &kp.priv, &clientPub)
	if subtle.ConstantTimeCompare(secret[:], curve25519Zeros[:]) == 1 {
		return nil, errors.New("ssh: peer's curve25519 public value has wrong order")
	}

	hostKeyBytes := priv.PublicKey().Marshal()

	h := crypto.SHA256.New()
	magics.write(h)
	writeString(h, hostKeyBytes)
	writeString(h, kexInit.ClientPubKey)
	writeString(h, kp.pub[:])

	ki := new(big.Int).SetBytes(secret[:])
	K := make([]byte, intLength(ki))
	marshalInt(K, ki)
	h.Write(K)

	H := h.Sum(nil)

	sig, err := signAndMarshal(priv, rand, H, algo)
	if err != nil {
		return nil, err
	}

	reply := kexECDHReplyMsg{
		EphemeralPubKey: kp.pub[:],
		HostKey:         hostKeyBytes,
		Signature:       sig,
	}
	if err := c.writePacket(Marshal(&reply)); err != nil {
		return nil, err
	}
	return &kexResult{
		H:         H,
		K:         K,
		HostKey:   hostKeyBytes,
		Signature: sig,
		Hash:      crypto.SHA256,
	}, nil
}

// dhGEXSHA implements the diffie-hellman-group-exchange-sha1 and
// diffie-hellman-group-exchange-sha256 key agreement protocols,
// as described in RFC 4419
type dhGEXSHA struct {
	hashFunc crypto.Hash
	JsonLog  *gexJsonLog
}

type gexJsonLog struct {
	Parameters      *ztoolsKeys.DHParams  `json:"dh_params,omitempty"`
	ServerSignature *JsonSignature        `json:"server_signature,omitempty"`
	ServerHostKey   *ServerHostKeyJsonLog `json:"server_host_key,omitempty"`
}

func (gex *dhGEXSHA) MarshalJSON() ([]byte, error) {
	return json.Marshal(gex.JsonLog)
}

func (gex *dhGEXSHA) GetNew(keyType string) kexAlgorithm {
	switch keyType {
	case kexAlgoDHGEXSHA1:
		ret := new(dhGEXSHA)
		ret.hashFunc = crypto.SHA1
		ret.JsonLog = new(gexJsonLog)
		ret.JsonLog.Parameters = new(ztoolsKeys.DHParams)
		return ret

	case kexAlgoDHGEXSHA256:
		ret := new(dhGEXSHA)
		ret.hashFunc = crypto.SHA256
		ret.JsonLog = new(gexJsonLog)
		ret.JsonLog.Parameters = new(ztoolsKeys.DHParams)
		return ret

	default:
		panic("Unimplemented GEX selected")
	}
}

func (gex *dhGEXSHA) Client(c packetConn, randSource io.Reader, magics *handshakeMagics, config *Config) (*kexResult, error) {
	// Send GexRequest
	kexDHGexRequest := kexDHGexRequestMsg{
		MinBits:      uint32(config.GexMinBits),
		PreferedBits: uint32(config.GexPreferredBits),
		MaxBits:      uint32(config.GexMaxBits),
	}
	if err := c.writePacket(Marshal(&kexDHGexRequest)); err != nil {
		return nil, err
	}

	// Receive GexGroup
	packet, err := c.readPacket()
	if err != nil {
		return nil, err
	}

	var msg kexDHGexGroupMsg
	if err = Unmarshal(packet, &msg); err != nil {
		return nil, err
	}

	if gex.JsonLog != nil {
		gex.JsonLog.Parameters.Prime = msg.P
		gex.JsonLog.Parameters.Generator = msg.G
	}

	// reject if p's bit length < dhGroupExchangeMinimumBits or > dhGroupExchangeMaximumBits
	if msg.P.BitLen() < int(config.GexMinBits) || msg.P.BitLen() > int(config.GexMaxBits) {
		return nil, fmt.Errorf("ssh: server-generated gex p is out of range (%d bits)", msg.P.BitLen())
	}

	// Check if g is safe by verifying that 1 < g < p-1
	pMinusOne := new(big.Int).Sub(msg.P, bigOne)
	if msg.G.Cmp(bigOne) <= 0 || msg.G.Cmp(pMinusOne) >= 0 {
		return nil, errors.New("ssh: server provided gex g is not safe")
	}

	// Send GexInit
	pHalf := new(big.Int).Rsh(msg.P, 1)
	x, err := rand.Int(randSource, pHalf)
	if err != nil {
		return nil, err
	}
	X := new(big.Int).Exp(msg.G, x, msg.P)
	kexDHGexInit := kexDHGexInitMsg{
		X: X,
	}

	if gex.JsonLog != nil && config.Verbose {
		gex.JsonLog.Parameters.ClientPrivate = x
		gex.JsonLog.Parameters.ClientPublic = X
	}

	if err := c.writePacket(Marshal(&kexDHGexInit)); err != nil {
		return nil, err
	}

	// Receive GexReply
	packet, err = c.readPacket()
	if err != nil {
		return nil, err
	}

	var kexDHGexReply kexDHGexReplyMsg
	if err = Unmarshal(packet, &kexDHGexReply); err != nil {
		return nil, err
	}

	if gex.JsonLog != nil {
		gex.JsonLog.Parameters.ServerPublic = kexDHGexReply.Y
		gex.JsonLog.ServerSignature = new(JsonSignature)
		gex.JsonLog.ServerSignature.Raw = kexDHGexReply.Signature
		gex.JsonLog.ServerSignature.Parsed, _, _ = parseSignatureBody(kexDHGexReply.Signature)
		gex.JsonLog.ServerHostKey = LogServerHostKey(kexDHGexReply.HostKey)
	}

	if kexDHGexReply.Y.Cmp(bigOne) <= 0 || kexDHGexReply.Y.Cmp(pMinusOne) >= 0 {
		return nil, errors.New("ssh: DH parameter out of bounds")
	}
	kInt := new(big.Int).Exp(kexDHGexReply.Y, x, msg.P)

	// Check if k is safe by verifying that k > 1 and k < p - 1
	if kInt.Cmp(bigOne) <= 0 || kInt.Cmp(pMinusOne) >= 0 {
		return nil, errors.New("ssh: derived k is not safe")
	}

	h := gex.hashFunc.New()
	magics.write(h)
	writeString(h, kexDHGexReply.HostKey)
	binary.Write(h, binary.BigEndian, uint32(config.GexMinBits))
	binary.Write(h, binary.BigEndian, uint32(config.GexPreferredBits))
	binary.Write(h, binary.BigEndian, uint32(config.GexMaxBits))
	writeInt(h, msg.P)
	writeInt(h, msg.G)
	writeInt(h, X)
	writeInt(h, kexDHGexReply.Y)
	K := make([]byte, intLength(kInt))
	marshalInt(K, kInt)
	h.Write(K)

	return &kexResult{
		H:         h.Sum(nil),
		K:         K,
		HostKey:   kexDHGexReply.HostKey,
		Signature: kexDHGexReply.Signature,
		Hash:      gex.hashFunc,
	}, nil
}

// Server half implementation of the Diffie Hellman Key Exchange with SHA1 and SHA256.
//
// This is a minimal implementation to satisfy the automated tests.
func (gex dhGEXSHA) Server(c packetConn, randSource io.Reader, magics *handshakeMagics, priv AlgorithmSigner, algo string, config *Config) (result *kexResult, err error) {
	// Receive GexRequest
	packet, err := c.readPacket()
	if err != nil {
		return
	}
	var kexDHGexRequest kexDHGexRequestMsg
	if err = Unmarshal(packet, &kexDHGexRequest); err != nil {
		return
	}

	// Send GexGroup
	// This is the group called diffie-hellman-group14-sha1 in RFC
	// 4253 and Oakley Group 14 in RFC 3526.
	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
	g := big.NewInt(2)

	msg := &kexDHGexGroupMsg{
		P: p,
		G: g,
	}
	if err := c.writePacket(Marshal(msg)); err != nil {
		return nil, err
	}

	// Receive GexInit
	packet, err = c.readPacket()
	if err != nil {
		return
	}
	var kexDHGexInit kexDHGexInitMsg
	if err = Unmarshal(packet, &kexDHGexInit); err != nil {
		return
	}

	pHalf := new(big.Int).Rsh(p, 1)

	y, err := rand.Int(randSource, pHalf)
	if err != nil {
		return
	}
	Y := new(big.Int).Exp(g, y, p)

	pMinusOne := new(big.Int).Sub(p, bigOne)
	if kexDHGexInit.X.Cmp(bigOne) <= 0 || kexDHGexInit.X.Cmp(pMinusOne) >= 0 {
		return nil, errors.New("ssh: DH parameter out of bounds")
	}
	kInt := new(big.Int).Exp(kexDHGexInit.X, y, p)

	hostKeyBytes := priv.PublicKey().Marshal()

	h := gex.hashFunc.New()
	magics.write(h)
	writeString(h, hostKeyBytes)
	binary.Write(h, binary.BigEndian, uint32(config.GexMinBits))
	binary.Write(h, binary.BigEndian, uint32(config.GexPreferredBits))
	binary.Write(h, binary.BigEndian, uint32(config.GexMaxBits))
	writeInt(h, p)
	writeInt(h, g)
	writeInt(h, kexDHGexInit.X)
	writeInt(h, Y)

	K := make([]byte, intLength(kInt))
	marshalInt(K, kInt)
	h.Write(K)

	H := h.Sum(nil)

	// H is already a hash, but the hostkey signing will apply its
	// own key-specific hash algorithm.
	sig, err := signAndMarshal(priv, randSource, H, algo)
	if err != nil {
		return nil, err
	}

	kexDHGexReply := kexDHGexReplyMsg{
		HostKey:   hostKeyBytes,
		Y:         Y,
		Signature: sig,
	}
	packet = Marshal(&kexDHGexReply)

	err = c.writePacket(packet)

	return &kexResult{
		H:         H,
		K:         K,
		HostKey:   hostKeyBytes,
		Signature: sig,
		Hash:      gex.hashFunc,
	}, err
}
