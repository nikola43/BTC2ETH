package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/fatih/color"
)

type Wallet struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

func main() {

	wif, err := networks["btc"].CreatePrivateKey()
	if err != nil {
		log.Fatal(err)
	}
	pk := wif.String()

	address, err := networks["btc"].GetAddress(wif)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(color.CyanString("BTC Public Key: "), color.YellowString(address.EncodeAddress()))
	fmt.Println(color.CyanString("BTC Private Key: "), color.YellowString(pk))
	fmt.Println()

	ethDerivedPrivateKey := HashValue(pk)
	ethDerivedPublicKey, err := GenerateAddressFromPlainPrivateKey(ethDerivedPrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(color.CyanString("ETH Derived Public Key: "), color.YellowString(ethDerivedPublicKey.Hex()))
	fmt.Println(color.CyanString("ETH Derived Private Key: "), color.YellowString(ethDerivedPrivateKey))

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
