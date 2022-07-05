package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/pem"

	"golang.org/x/crypto/ssh"
)

func GenEd25519Keys(passphrase []byte, memo string) (privateKey []byte, publicKey []byte, err error) {
	s := &SSHKeyPair{
		keyType:    Ed25519,
		passphrase: passphrase,
		memo:       memo,
	}
	err = s.generateEd25519Keys()
	if err != nil {
		return
	}
	//private without Proc-Type
	var block *pem.Block
	block, err = s.pemBlock(s.passphrase)
	////private with Proc-Type: 4,ENCRYPTED DEK-Info
	//var privateByte []byte
	//privateByte, err = x509.MarshalPKCS8PrivateKey(s.privateKey)
	//if err != nil {
	//	return
	//}
	//block = &pem.Block{
	//	Type:  "OPENSSH PRIVATE KEY",
	//	Bytes: privateByte,
	//}
	//block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, s.passphrase, x509.PEMCipherAES256)
	if err != nil {
		return
	}
	privateKey = pem.EncodeToMemory(block)
	publicKey = s.PublicKey()
	return
}

func GenAuthMethod(signer ssh.Signer) (authMethod ssh.AuthMethod) {
	return ssh.PublicKeys(signer)
}

func GenAuthorizedKey(publicKey ssh.PublicKey) (authorizedKey []byte) {
	return ssh.MarshalAuthorizedKey(publicKey)
}

func ParseRawPrivateKeyWithPassphrase(privateKey []byte, passphrase []byte) (signer ssh.Signer, err error) {
	var key interface{}
	key, err = ssh.ParseRawPrivateKeyWithPassphrase(privateKey, passphrase)
	if err != nil {
		return
	}
	signer, err = ssh.NewSignerFromKey(key)
	return
}

func ParseRawPrivateKey(privateKey []byte) (signer ssh.Signer, err error) {
	var key interface{}
	key, err = ssh.ParseRawPrivateKey(privateKey)
	if err != nil {
		return
	}
	signer, err = ssh.NewSignerFromKey(key)
	return
}

func generateSigner() (ssh.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(key)
}

func parsePtyRequest(s []byte) (pty Pty, ok bool) {
	term, s, ok := parseString(s)
	if !ok {
		return
	}
	width32, s, ok := parseUint32(s)
	if !ok {
		return
	}
	height32, _, ok := parseUint32(s)
	if !ok {
		return
	}
	pty = Pty{
		Term: term,
		Window: Window{
			Width:  int(width32),
			Height: int(height32),
		},
	}
	return
}

func parseWinchRequest(s []byte) (win Window, ok bool) {
	width32, s, ok := parseUint32(s)
	if width32 < 1 {
		ok = false
	}
	if !ok {
		return
	}
	height32, _, ok := parseUint32(s)
	if height32 < 1 {
		ok = false
	}
	if !ok {
		return
	}
	win = Window{
		Width:  int(width32),
		Height: int(height32),
	}
	return
}

func parseString(in []byte) (out string, rest []byte, ok bool) {
	if len(in) < 4 {
		return
	}
	length := binary.BigEndian.Uint32(in)
	if uint32(len(in)) < 4+length {
		return
	}
	out = string(in[4 : 4+length])
	rest = in[4+length:]
	ok = true
	return
}

func parseUint32(in []byte) (uint32, []byte, bool) {
	if len(in) < 4 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(in), in[4:], true
}
