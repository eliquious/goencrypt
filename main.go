package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "golang.org/x/crypto/ripemd160"

	"compress/gzip"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	// Goencrypt app
	app  = kingpin.New("goencrypt", "A command line tool for encrypting files")
	bits = app.Flag("bits", "Bits for keys").Default("4096").Int()
	privateKey = app.Flag("private", "Private key").String()
	publicKey = app.Flag("public", "Public key").String()
	signatureFile = app.Flag("sig", "Signature File").String()

	// Generates new public and private keys
	keyGenCmd       = app.Command("keygen", "Generates a new public/private key pair")
	keyOutputPrefix = keyGenCmd.Arg("prefix", "Prefix of key files").Required().String()
	keyOutputDir    = keyGenCmd.Flag("d", "Output directory of key files").Default(".").String()

	// Base command for entity sub-commands
	entityCmd        = app.Command("entity", "Generates a PGP entity")
	entityOutputFile = entityCmd.Flag("o", "Output file of entity").Default("./entity.asc").String()
	identityName     = entityCmd.Flag("name", "Name of identity").Default("").String()
	identityComment  = entityCmd.Flag("comment", "Command for identity").Default("").String()
	identityEmail    = entityCmd.Flag("email", "Email for identity").Default("").String()

	// Creates a new entity
	createEntityCmd = entityCmd.Command("new", "Create new entity")

	// Adds an identity to an entity
	addIdentityCmd            = entityCmd.Command("add", "Add an identity to the entity")
	addIdentityFile           = addIdentityCmd.Arg("entity file", "Entity to add the identity to").Required().String()
	addIdentityPrivateKeyFile = addIdentityCmd.Flag("key", "Private key of entity").String()

	// Encrypts a file with a public key
	encryptionCmd = app.Command("encrypt", "Encrypt a file")

	// Signs a file with a private key
	signCmd = app.Command("sign", "Sign a file")

	// Verifies a file was signed with the public key
	verifyCmd = app.Command("verify", "Verify a signature")

	// Decrypts a file with a private key
	decryptionCmd = app.Command("decrypt", "Decrypt a file")
)

func main() {
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {

	// generate keys
	case keyGenCmd.FullCommand():
		generateKeys()
	case createEntityCmd.FullCommand():
		newEntity()
	case encryptionCmd.FullCommand():
		encryptFile()
	case signCmd.FullCommand():
		signFile()
	case verifyCmd.FullCommand():
		verifyFile()
	case decryptionCmd.FullCommand():
		decryptFile()
	case addIdentityCmd.FullCommand():
		privKey := decodePrivateKey(*addIdentityPrivateKeyFile)

		entityList := decodeKeyRing(*addIdentityFile)
		var config packet.Config
		for _, ent := range entityList {
			ent.PrivateKey = privKey
			addIdentity(false, config, ent)

			// Sign identities
			for _, id := range ent.Identities {
				kingpin.Errorf("Identity: %#v", *ent.PrivateKey)
				err := id.SelfSignature.SignUserId(id.UserId.Id, ent.PrimaryKey, ent.PrivateKey, nil)
				if err != nil {
					kingpin.FatalIfError(err, "Error signing identity: %s", err)
					return
				}
			}

			// Sign subkeys
			for _, subkey := range ent.Subkeys {
				err := subkey.Sig.SignKey(subkey.PublicKey, ent.PrivateKey, nil)
				if err != nil {
					kingpin.FatalIfError(err, "Error signing subkey: %s", err)
				}
			}

			entityFile, err := os.Create(*entityOutputFile)
			kingpin.FatalIfError(err, "Error creating entity file: %s", err)
			defer entityFile.Close()

			w, err := armor.Encode(entityFile, openpgp.PublicKeyType, map[string]string{})
			err = ent.Serialize(w)
			kingpin.Errorf("identities: %d", len(ent.Identities))
			kingpin.Errorf("subkeys: %d", len(ent.Subkeys))
			kingpin.FatalIfError(err, "Error serializing entity: %s", err)
			w.Close()

			break
		}

	default:
		kingpin.FatalUsage("Unknown command")
	}
}

func encodePrivateKey(out io.Writer, key *rsa.PrivateKey) {
	w, err := armor.Encode(out, openpgp.PrivateKeyType, make(map[string]string))
	kingpin.FatalIfError(err, "Error creating OpenPGP Armor: %s", err)

	pgpKey := packet.NewRSAPrivateKey(time.Now(), key)
	kingpin.FatalIfError(pgpKey.Serialize(w), "Error serializing private key: %s", err)
	kingpin.FatalIfError(w.Close(), "Error serializing private key: %s", err)
}

func decodePrivateKey(filename string) *packet.PrivateKey {

	// open ascii armored private key
	in, err := os.Open(filename)
	kingpin.FatalIfError(err, "Error opening private key: %s", err)
	defer in.Close()

	block, err := armor.Decode(in)
	kingpin.FatalIfError(err, "Error decoding OpenPGP Armor: %s", err)

	if block.Type != openpgp.PrivateKeyType {
		kingpin.FatalIfError(errors.New("Invalid private key file"), "Error decoding private key")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	kingpin.FatalIfError(err, "Error reading private key")

	key, ok := pkt.(*packet.PrivateKey)
	if !ok {
		kingpin.FatalIfError(errors.New("Invalid private key"), "Error parsing private key")
	}
	return key
}

func encodePublicKey(out io.Writer, key *rsa.PrivateKey) {
	w, err := armor.Encode(out, openpgp.PublicKeyType, make(map[string]string))
	kingpin.FatalIfError(err, "Error creating OpenPGP Armor: %s", err)

	pgpKey := packet.NewRSAPublicKey(time.Now(), &key.PublicKey)
	kingpin.FatalIfError(pgpKey.Serialize(w), "Error serializing public key: %s", err)
	kingpin.FatalIfError(w.Close(), "Error serializing public key: %s", err)
}

func decodePublicKey(filename string) *packet.PublicKey {

	// open ascii armored public key
	in, err := os.Open(filename)
	kingpin.FatalIfError(err, "Error opening public key: %s", err)
	defer in.Close()

	block, err := armor.Decode(in)
	kingpin.FatalIfError(err, "Error decoding OpenPGP Armor: %s", err)

	if block.Type != openpgp.PublicKeyType {
		kingpin.FatalIfError(errors.New("Invalid private key file"), "Error decoding private key")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	kingpin.FatalIfError(err, "Error reading private key")

	key, ok := pkt.(*packet.PublicKey)
	if !ok {
		kingpin.FatalIfError(errors.New("Invalid public key"), "Error parsing public key")
	}
	return key
}

func decodeSignature(filename string) *packet.Signature {

	// open ascii armored public key
	in, err := os.Open(filename)
	kingpin.FatalIfError(err, "Error opening public key: %s", err)
	defer in.Close()

	block, err := armor.Decode(in)
	kingpin.FatalIfError(err, "Error decoding OpenPGP Armor: %s", err)

	if block.Type != openpgp.SignatureType {
		kingpin.FatalIfError(errors.New("Invalid signature file"), "Error decoding signature")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	kingpin.FatalIfError(err, "Error reading signature")

	sig, ok := pkt.(*packet.Signature)
	if !ok {
		kingpin.FatalIfError(errors.New("Invalid signature"), "Error parsing signature")
	}
	return sig
}

func encryptFile() {
	pubKey := decodePublicKey(*publicKey)
	privKey := decodePrivateKey(*privateKey)

	to := createEntityFromKeys(pubKey, privKey)

	w, err := armor.Encode(os.Stdout, "Message", make(map[string]string))
	kingpin.FatalIfError(err, "Error creating OpenPGP Armor: %s", err)
	defer w.Close()

	plain, err := openpgp.Encrypt(w, []*openpgp.Entity{to}, nil, nil, nil)
	kingpin.FatalIfError(err, "Error creating entity for encryption")
	defer plain.Close()

	compressed, err := gzip.NewWriterLevel(plain, gzip.BestCompression)
	kingpin.FatalIfError(err, "Invalid compression level")

	n, err := io.Copy(compressed, os.Stdin)
	kingpin.FatalIfError(err, "Error writing encrypted file")
	kingpin.Errorf("Encrypted %d bytes", n)

	compressed.Close()
}

func decryptFile() {
	pubKey := decodePublicKey(*publicKey)
	privKey := decodePrivateKey(*privateKey)

	entity := createEntityFromKeys(pubKey, privKey)

	block, err := armor.Decode(os.Stdin)
	kingpin.FatalIfError(err, "Error reading OpenPGP Armor: %s", err)

	if block.Type != "Message" {
		kingpin.FatalIfError(err, "Invalid message type")
	}

	var entityList openpgp.EntityList
	entityList = append(entityList, entity)
	
	md, err := openpgp.ReadMessage(block.Body, entityList, nil, nil)
	kingpin.FatalIfError(err, "Error reading message")

	compressed, err := gzip.NewReader(md.UnverifiedBody)
	kingpin.FatalIfError(err, "Invalid compression level")
	defer compressed.Close()

	n, err := io.Copy(os.Stdout, compressed)
	kingpin.FatalIfError(err, "Error reading encrypted file")
	kingpin.Errorf("Decrypted %d bytes", n)
}

func signFile() {
	pubKey := decodePublicKey(*publicKey)
	privKey := decodePrivateKey(*privateKey)

	signer := createEntityFromKeys(pubKey, privKey)

	err := openpgp.ArmoredDetachSign(os.Stdout, signer, os.Stdin, nil)
	kingpin.FatalIfError(err, "Error signing input")
}

func verifyFile() {
	pubKey := decodePublicKey(*publicKey)
	sig := decodeSignature(*signatureFile)

	hash := sig.Hash.New()
	io.Copy(hash, os.Stdin)

	err := pubKey.VerifySignature(hash, sig)
	kingpin.FatalIfError(err, "Error signing input")
	kingpin.Errorf("Verified signature")
}

func createEntityFromKeys(pubKey *packet.PublicKey, privKey *packet.PrivateKey) *openpgp.Entity {
	config := packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		CompressionConfig: &packet.CompressionConfig{
			Level: 9,
		},
		RSABits: *bits,
	}
	currentTime := config.Now()
	uid := packet.NewUserId("", "", "")

	e := openpgp.Entity{
		PrimaryKey: pubKey,
		PrivateKey: privKey,
		Identities: make(map[string]*openpgp.Identity),
	}
	isPrimaryId := false

	e.Identities[uid.Id] = &openpgp.Identity{
		Name:   uid.Name,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime: currentTime,
			SigType:      packet.SigTypePositiveCert,
			PubKeyAlgo:   packet.PubKeyAlgoRSA,
			Hash:         config.Hash(),
			IsPrimaryId:  &isPrimaryId,
			FlagsValid:   true,
			FlagSign:     true,
			FlagCertify:  true,
			IssuerKeyId:  &e.PrimaryKey.KeyId,
		},
	}

	keyLifetimeSecs := uint32(86400 * 365)

	e.Subkeys = make([]openpgp.Subkey, 1)
	e.Subkeys[0] = openpgp.Subkey{
		PublicKey: pubKey,
		PrivateKey: privKey,
		Sig: &packet.Signature{
			CreationTime:              currentTime,
			SigType:                   packet.SigTypeSubkeyBinding,
			PubKeyAlgo:                packet.PubKeyAlgoRSA,
			Hash:                      config.Hash(),
			PreferredHash:             []uint8{8}, // SHA-256
			FlagsValid:                true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &e.PrimaryKey.KeyId,
			KeyLifetimeSecs:           &keyLifetimeSecs,
		},
	}
	return &e
}

func newEntity() {
	ent, err := openpgp.NewEntity(*identityName, *identityComment, *identityEmail, &packet.Config{
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		CompressionConfig: &packet.CompressionConfig{
			Level: 9,
		},
		RSABits: *bits,
	})
	kingpin.FatalIfError(err, "Error creating entity: %s", err)

	// Sign identities
	for _, id := range ent.Identities {
		err := id.SelfSignature.SignUserId(id.UserId.Id, ent.PrimaryKey, ent.PrivateKey, nil)
		if err != nil {
			kingpin.FatalIfError(err, "Error signing identity: %s", err)
			return
		}
	}

	// Sign subkeys
	for _, subkey := range ent.Subkeys {

		priv, err := os.Create(filepath.Join(*entityOutputFile + ".subkey.key"))
		kingpin.FatalIfError(err, "Error writing private key to file: %s", err)
		defer priv.Close()

		encodePrivateKey(priv, subkey.PrivateKey.PrivateKey.(*rsa.PrivateKey))

		err = subkey.Sig.SignKey(subkey.PublicKey, ent.PrivateKey, nil)
		if err != nil {
			kingpin.FatalIfError(err, "Error signing subkey: %s", err)
		}
	}

	entityFile, err := os.Create(*entityOutputFile)
	kingpin.FatalIfError(err, "Error creating entity file: %s", err)
	defer entityFile.Close()

	w, err := armor.Encode(entityFile, openpgp.PublicKeyType, map[string]string{})
	err = ent.Serialize(w)
	kingpin.Errorf("identities: %d", len(ent.Identities))
	kingpin.Errorf("subkeys: %d", len(ent.Subkeys))
	kingpin.FatalIfError(err, "Error serializing entity: %s", err)
	w.Close()

	priv, err := os.Create(filepath.Join(*entityOutputFile + ".key"))
	kingpin.FatalIfError(err, "Error writing private key to file: %s", err)
	defer priv.Close()

	encodePrivateKey(priv, ent.PrivateKey.PrivateKey.(*rsa.PrivateKey))
}

// func createNewEntity() {
// 	key, err := rsa.GenerateKey(rand.Reader, *bits)
// 	kingpin.FatalIfError(err, "Error generating RSA key: %s", err)

// 	currentTime := time.Now()
// 	e := &openpgp.Entity{
// 		PrimaryKey: packet.NewRSAPublicKey(currentTime, &key.PublicKey),
// 		PrivateKey: packet.NewRSAPrivateKey(currentTime, key),
// 		Identities: make(map[string]*openpgp.Identity),
// 	}

// 	var config packet.Config
// 	addIdentity(true, config, e)

// 	entityFile, err := os.Create(*entityOutputFile)
// 	kingpin.FatalIfError(err, "Error creating entity file: %s", err)
// 	defer entityFile.Close()

// 	w, err := armor.Encode(entityFile, openpgp.PublicKeyType, map[string]string{})
// 	e.Serialize(w)
// 	w.Close()

// 	priv, err := os.Create(filepath.Join(*entityOutputFile + ".key"))
// 	kingpin.FatalIfError(err, "Error writing private key to file: %s", err)
// 	defer priv.Close()

// 	encodePrivateKey(priv, key)
// }

func addIdentity(isPrimary bool, config packet.Config, entity *openpgp.Entity) {
	currentTime := config.Now()
	uid := packet.NewUserId(*identityName, *identityComment, *identityEmail)

	encryptingPriv, err := rsa.GenerateKey(rand.Reader, *bits)
	kingpin.FatalIfError(err, "Error generating RSA key: %s", err)

	entity.Identities[uid.Id] = &openpgp.Identity{
		Name:   uid.Name,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime: currentTime,
			SigType:      packet.SigTypePositiveCert,
			PubKeyAlgo:   packet.PubKeyAlgoRSA,
			Hash:         config.Hash(),
			IsPrimaryId:  &isPrimary,
			FlagsValid:   true,
			FlagSign:     true,
			FlagCertify:  true,
			IssuerKeyId:  &entity.PrimaryKey.KeyId,
		},
	}

	keyLifetimeSecs := uint32(86400 * 365 * 10)
	subkey := openpgp.Subkey{
		PublicKey:  packet.NewRSAPublicKey(currentTime, &encryptingPriv.PublicKey),
		PrivateKey: packet.NewRSAPrivateKey(currentTime, encryptingPriv),

		Sig: &packet.Signature{
			CreationTime:              currentTime,
			SigType:                   packet.SigTypeSubkeyBinding,
			PubKeyAlgo:                packet.PubKeyAlgoRSA,
			Hash:                      config.Hash(),
			FlagsValid:                true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &entity.PrimaryKey.KeyId,
			KeyLifetimeSecs:           &keyLifetimeSecs,
		},
	}
	subkey.PublicKey.IsSubkey = true
	subkey.PrivateKey.IsSubkey = true
	entity.Subkeys = append(entity.Subkeys, subkey)
}

func decodeKeyRing(filename string) openpgp.EntityList {

	// open ascii armored private key
	entityFile, err := os.Open(filename)
	kingpin.FatalIfError(err, "Error opening entity: %s", err)
	defer entityFile.Close()

	// read key ring
	entity, err := openpgp.ReadArmoredKeyRing(entityFile)
	kingpin.FatalIfError(err, "Error reading entity: %s", err)

	for _, e := range entity {
		kingpin.Errorf("Entity: %#v", *e)
	}
	return entity
}

func generateKeys() {
	key, err := rsa.GenerateKey(rand.Reader, *bits)
	kingpin.FatalIfError(err, "Error generating RSA key: %s", err)

	priv, err := os.Create(filepath.Join(*keyOutputDir, *keyOutputPrefix+".privkey"))
	kingpin.FatalIfError(err, "Error writing private key to file: %s", err)
	defer priv.Close()

	pub, err := os.Create(filepath.Join(*keyOutputDir, *keyOutputPrefix+".pubkey"))
	kingpin.FatalIfError(err, "Error writing public key to file: %s", err)
	defer pub.Close()

	encodePrivateKey(priv, key)
	encodePublicKey(pub, key)
}
