package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/fatih/color"
	"golang.org/x/crypto/sha3"
)

type Wallet struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

func main() {

	// BTC to ETH
	fmt.Println(color.YellowString("BTC to ETH"))

	btcWallet := GenerateBTCWallet()
	fmt.Println(color.CyanString("BTC Public Key: "), color.YellowString(btcWallet.PublicKey))
	fmt.Println(color.CyanString("BTC Private Key: "), color.YellowString(btcWallet.PrivateKey))
	fmt.Println()

	ethDerivedPrivateKey := HashValue(btcWallet.PrivateKey)
	ethDerivedPublicKey, err := GenerateAddressFromPlainPrivateKey(ethDerivedPrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(color.CyanString("ETH Derived Public Key: "), color.YellowString(ethDerivedPublicKey.Hex()))
	fmt.Println(color.CyanString("ETH Derived Private Key: "), color.YellowString(ethDerivedPrivateKey))
	fmt.Println()

	// ETH to BTC
	fmt.Println(color.YellowString("BTC to ETH"))

	ethWallet := GenerateETHWallet()
	fmt.Println(color.CyanString("ETH Public Key: "), color.YellowString(ethWallet.PublicKey))
	fmt.Println(color.CyanString("ETH Private Key: "), color.YellowString(ethWallet.PrivateKey))
	fmt.Println()

	btcDerivedPrivateKey := HashValue(ethWallet.PrivateKey)
	btcDerivedPublicKey, err := GenerateAddressFromPlainPrivateKey(ethDerivedPrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(color.CyanString("BTC Derived Public Key: "), color.YellowString(btcDerivedPublicKey.Hex()))
	fmt.Println(color.CyanString("BTC Derived Private Key: "), color.YellowString(btcDerivedPrivateKey))
	fmt.Println()

	// Encode example data with the modified base58 encoding scheme.
	data := []byte(ethWallet.PrivateKey)
	encoded := base58.Encode(data)

	// Show the encoded data.
	fmt.Println("Encoded Data:", encoded[:52])

}

func GenerateBTCWallet() Wallet {
	wif, err := networks["btc"].CreatePrivateKey()
	if err != nil {
		log.Fatal(err)
	}
	pk := wif.String()

	address, err := networks["btc"].GetAddress(wif)
	if err != nil {
		log.Fatal(err)
	}
	wallet := Wallet{
		PublicKey:  address.EncodeAddress(),
		PrivateKey: pk,
	}
	return wallet

}

func GenerateETHWallet() Wallet {

	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	privateKeyBytes := crypto.FromECDSA(privateKey)

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)

	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()

	hash := sha3.NewLegacyKeccak256()
	hash.Write(publicKeyBytes[1:])

	wallet := Wallet{
		PublicKey:  address,
		PrivateKey: hexutil.Encode(privateKeyBytes)[2:],
	}

	return wallet
}

func GenerateAddressFromPlainPrivateKey(pk string) (common.Address, error) {

	var address common.Address
	privateKey, err := crypto.HexToECDSA(pk)
	if err != nil {
		return address, err
	}

	publicKeyECDSA, ok := privateKey.Public().(*ecdsa.PublicKey)
	if !ok {
		return address, errors.New("error casting public key to ECDSA")
	}

	return crypto.PubkeyToAddress(*publicKeyECDSA), nil
}

func HashValue(value string) string {
	hash := sha256.New()
	hash.Write([]byte(value))
	return hex.EncodeToString(hash.Sum(nil))
}
