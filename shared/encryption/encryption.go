package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"shared/mongo_schemes"
)

func Pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func AesEncryptCBC(key []byte, plain []byte) ([]byte, error) {
    iv := make([]byte, aes.BlockSize)
    _, err := rand.Read(iv)
    if err != nil {
        return nil, err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    paddedBody := Pkcs7Pad(plain, aes.BlockSize)
    cipherText := make([]byte, len(paddedBody))
    mode := cipher.NewCBCEncrypter(block, iv)
    mode.CryptBlocks(cipherText, paddedBody)

    result := append(iv, cipherText...)

    return result, nil
}

func AesEncryptGCM(key []byte, plain []byte) ([]byte, error) {
    nonce := make([]byte, 12)
    _, err := rand.Read(nonce)
    if err != nil {
        return nil, err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    ciphertext := aesgcm.Seal(nil, nonce, plain, nil)

    result := append(nonce, ciphertext...)

    return result, nil
}

func EncryptEmail(message []byte) ([]byte, []byte, error) {
    email_key := make([]byte, 32)
    _, err := rand.Read(email_key)
    if err != nil {
        return nil, nil, err 
    }

    encrypted_body, err := AesEncryptCBC(email_key, message)
    return encrypted_body, email_key, err
}

type EncryptedKey struct {
    SecondStageKey []byte 
    CipherText []byte 
    UsedKey []byte
}

func GenerateEncryptedKey(email_key []byte, dh_priv ecdh.PrivateKey, user *mongo_schemes.User) (EncryptedKey, error) {
    recipient_key := user.MainKey

    dh_pub_key, err := ecdh.P256().NewPublicKey(recipient_key.DHPublicKey)
    if err != nil {
        return EncryptedKey{}, err
    }

    dh_shared_secret, err := dh_priv.ECDH(dh_pub_key)
    if err != nil {
        return EncryptedKey{}, err
    }

    mlkem_pub, err := mlkem.NewEncapsulationKey1024(recipient_key.MLKEMPublicKey)

    ciphertext, mlkem_shared_secret := mlkem_pub.Encapsulate()
    if err != nil {
        return EncryptedKey{}, err
    }

    concatenated := append(mlkem_shared_secret, dh_shared_secret...)

    shared_secret := sha256.Sum256(concatenated)

    encrypted_email_key, err := AesEncryptGCM(shared_secret[:], email_key)

    return EncryptedKey{
        SecondStageKey: encrypted_email_key,
        CipherText: ciphertext,
        UsedKey: recipient_key.KeyId,
    }, nil
}
