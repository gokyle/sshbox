/*
 * sshbox is a utility to encrypt a file using SSH keys.
 */
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/cryptobox/gocryptobox/secretbox"
	"github.com/gokyle/ecies"
	"github.com/gokyle/sshkey"
	"io/ioutil"
	"os"
	"regexp"
)

type boxPackage struct {
	LockedKey []byte
	Box       []byte
}

type messageBox struct {
	Message   []byte
	Signature []byte `asn1:"optional"`
}

type sshPublicKey struct {
	Algorithm []byte
	Modulus   []byte
	Exponent  []byte
}

var pubkeyRegexp = regexp.MustCompile("(?m)^ssh-... (\\S+).*$")
var remoteCheck = regexp.MustCompile("^https?://")

func main() {
	flArmour := flag.Bool("a", false, "ASCII armour the box")
	flDecrypt := flag.Bool("d", false, "decrypt file")
	flEncrypt := flag.Bool("e", false, "encrypt file")
	flKeyFile := flag.String("k", "", "SSH key file")
	flSignKey := flag.String("s", "", "SSH private key for signing")
	flVerifyKey := flag.String("v", "", "SSH public for signature verification")
	flag.Parse()

	if *flDecrypt && *flEncrypt {
		fmt.Println("[!] only one of -d or -e can be specified!")
		os.Exit(1)
	}

	if *flDecrypt && *flSignKey != "" {
		fmt.Println("[!] cannot sign encrypted message.")
		os.Exit(1)
	} else if *flEncrypt && *flVerifyKey != "" {
		fmt.Println("[!] cannot verify plaintext message.")
		os.Exit(1)
	}

	if flag.NArg() != 2 {
		fmt.Println("[!] source and target must both be specified.")
		fmt.Printf("\t%s [options] source target\n", os.Args[0])
		os.Exit(1)
	}
	source := flag.Args()[0]
	target := flag.Args()[1]

	if *flKeyFile == "" {
		fmt.Println("[!] no key was specified!\n")
		os.Exit(1)
	}

	remote := remoteCheck.MatchString(*flKeyFile)
	if remote {
		if *flDecrypt {
			fmt.Println("[+] remotely fetching private keys is not allowed.")
			os.Exit(1)
		}
		fmt.Println("[+] will fetch key")
	}

	if *flEncrypt {
		err := encrypt(source, target, *flKeyFile, *flSignKey, !remote, *flArmour)
		if err != nil {
			fmt.Println("[!] failed.")
			os.Exit(1)
		}
		fmt.Println("[+] success")
		os.Exit(0)
	} else {
		err := decrypt(source, target, *flKeyFile, *flVerifyKey, *flArmour)
		if err != nil {
			fmt.Println("[!] failed.")
			os.Exit(1)
		}
		fmt.Println("[+] success.")
		os.Exit(0)
	}
}

// Generate a random box key, encrypt the key to the RSA public key,
// package the box appropriately, and write it out to a file.
func encrypt(in, out, keyfile, signkey string, local, armour bool) (err error) {
	pub, err := sshkey.LoadPublicKeyFile(keyfile, local)
	if err != nil {
		fmt.Printf("[!] failed to load the public key:\n\t%s\n",
			err.Error())
		return
	}
	switch pub.Type {
	case sshkey.KEY_RSA:
		err = encryptRSA(in, out, pub.Key.(*rsa.PublicKey), signkey,
			local, armour)
	case sshkey.KEY_ECDSA:
		err = encryptECDSA(in, out, pub.Key.(*ecdsa.PublicKey), signkey,
			local, armour)
	default:
		err = sshkey.ErrInvalidPrivateKey
		fmt.Println("[!]", err.Error())
	}
	return
}

func encryptRSA(in, out string, key *rsa.PublicKey, signkey string, local, armour bool) (err error) {
	boxKey, ok := secretbox.GenerateKey()
	if !ok {
		fmt.Println("[!] failed to generate the box key.")
		return
	}

	hash := sha256.New()
	lockedKey, err := rsa.EncryptOAEP(hash, rand.Reader, key, boxKey, nil)
	if err != nil {
		fmt.Println("[!] RSA encryption failed:", err.Error())
		return
	}

	message, err := ioutil.ReadFile(in)
	if err != nil {
		fmt.Println("[!]", err.Error())
		return
	}

	box, ok := secretbox.Seal(message, boxKey)
	if !ok {
		fmt.Println("[!] failed to seal the message.")
		err = fmt.Errorf("sealing failure")
		return
	}
	pkg, err := packageBox(lockedKey, box, armour)
	if err != nil {
		return
	}

	err = ioutil.WriteFile(out, pkg, 0644)
	if err != nil {
		fmt.Println("[!]", err.Error())
	}

	if err != nil {
		fmt.Println("[!]", err.Error())
	}
	return
}

func encryptECDSA(in, out string, key *ecdsa.PublicKey, signkey string, local, armour bool) (err error) {
	message, err := ioutil.ReadFile(in)
	if err != nil {
		fmt.Println("[!]", err.Error())
		return
	}

	eciesKey := ecies.ImportECDSAPublic(key)
	eciesKey.Params = ecies.ParamsFromCurve(key.Curve)
	box, error := ecies.Encrypt(rand.Reader, eciesKey, message, nil, nil)
	if error != nil {
		fmt.Println("[!]", err.Error())
		return
	}
	pkg, err := packageBox(nil, box, armour)
	if err != nil {
		return
	}

	err = ioutil.WriteFile(out, pkg, 0644)
	if err != nil {
		fmt.Println("[!]", err.Error())
	}

	if err != nil {
		fmt.Println("[!]", err.Error())
	}
	return
}

// packageBox actually handles boxing. It can output either PEM-encoded or
// DER-encoded boxes.
func packageBox(lockedKey, box []byte, armour bool) (pkg []byte, err error) {
	var pkgBox = boxPackage{lockedKey, box}

	pkg, err = asn1.Marshal(pkgBox)
	if err != nil {
		fmt.Println("[!] couldn't package the box")
		return
	}

	if armour {
		var block pem.Block
		block.Type = "SSHBOX ENCRYPTED FILE"
		block.Bytes = pkg
		pkg = pem.EncodeToMemory(&block)
	}
	return
}

// Decrypt loads the box, recovers the key using the RSA private key, open
// the box, and write the message to a file.
func decrypt(in, out, keyfile, verifykey string, armour bool) (err error) {
	key, keytype, err := sshkey.LoadPrivateKeyFile(keyfile)
	if err != nil {
		fmt.Printf("[!] failed to load the private key:\n\t%s\n",
			err.Error())
		return
	}

	switch keytype {
	case sshkey.KEY_RSA:
		return decryptRSA(in, out, key.(*rsa.PrivateKey), verifykey, armour)
	case sshkey.KEY_ECDSA:
		return decryptECDSA(in, out, key.(*ecdsa.PrivateKey), verifykey, armour)
	default:
		err = sshkey.ErrInvalidPublicKey
		fmt.Println("[!]", err.Error())
		return
	}
}

func decryptRSA(in, out string, key *rsa.PrivateKey, verifykey string, armour bool) (err error) {
	pkg, err := ioutil.ReadFile(in)
	if err != nil {
		fmt.Println("[!]", err.Error())
		return
	}

	lockedKey, box, err := unpackageBox(pkg)
	if err != nil {
		return
	}

	hash := sha256.New()
	boxKey, err := rsa.DecryptOAEP(hash, rand.Reader, key, lockedKey, nil)
	if err != nil {
		fmt.Println("[!] RSA decryption failed:", err.Error())
		return
	}

	message, ok := secretbox.Open(box, boxKey)
	if !ok {
		fmt.Println("[!] failed to open box.")
		err = fmt.Errorf("opening box failed")
		return
	}
	err = ioutil.WriteFile(out, message, 0644)
	return
}

func decryptECDSA(in, out string, key *ecdsa.PrivateKey, verifykey string, armour bool) (err error) {
	pkg, err := ioutil.ReadFile(in)
	if err != nil {
		fmt.Println("[!]", err.Error())
		return
	}

	_, box, err := unpackageBox(pkg)
	if err != nil {
		return
	}

	eciesKey := ecies.ImportECDSA(key)
	eciesKey.PublicKey.Params = ecies.ParamsFromCurve(key.PublicKey.Curve)

	message, err := eciesKey.Decrypt(rand.Reader, box, nil, nil)
	if err != nil {
		fmt.Println("[!]", err.Error())
		return
	}
	err = ioutil.WriteFile(out, message, 0644)
	return
}

// unpackageBox handles the loading of a box; it first attempts to decode the
// box as a DER-encoded box. If this fails, it attempts to decode the box as
// a PEM-encoded box.
func unpackageBox(pkg []byte) (lockedKey, box []byte, err error) {
	var pkgStruct boxPackage

	_, err = asn1.Unmarshal(pkg, &pkgStruct)
	if err == nil {
		return pkgStruct.LockedKey, pkgStruct.Box, nil
	}

	block, _ := pem.Decode(pkg)
	if block == nil || block.Type != "SSHBOX ENCRYPTED FILE" {
		fmt.Println("[!] invalid box.")
		err = fmt.Errorf("invalid box")
		return
	}
	_, err = asn1.Unmarshal(block.Bytes, &pkgStruct)
	return pkgStruct.LockedKey, pkgStruct.Box, err
}
