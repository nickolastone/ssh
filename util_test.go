package ssh

import (
	"golang.org/x/crypto/ssh"
	"testing"
)

func TestGenEd25519Keys(t *testing.T) {
	var passphrase = []byte("aWesom@83!372secRet")
	var memo = "testing@ssh.dev"
	var priKey, pubKey, err = GenEd25519Keys(passphrase, memo)
	if err != nil {
		t.Fatalf("GenEd25519Keys failed err:%s", err.Error())
		return
	}
	t.Logf("Gen PrivateKey \n%s\n PublicKey \n%s\n", priKey, pubKey)

	var signer ssh.Signer
	signer, err = ParseRawPrivateKeyWithPassphrase(priKey, passphrase)
	if err != nil {
		t.Fatalf("ParseRawPrivateKeyWithPassphrase failed err:%s", err.Error())
		return
	}

	t.Logf("Signer AuthMethod \n%s\n", GenAuthMethod(signer))
	t.Logf("Signer AuthorizedKey \n%s\n", GenAuthorizedKey(signer.PublicKey()))

}
