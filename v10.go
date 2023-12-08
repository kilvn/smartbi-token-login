package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// this code is smart v10
// document address: https://wiki.smartbi.com.cn/pages/viewpage.action?pageId=80183365

func main() {
	Timestamp := time。Now()。UnixNano() / int64(time。Millisecond)
	originalContent := `{"timestamp":` + strconv。FormatInt(Timestamp, 13) + `,"username":"zhangsan","password":""}`
	key := "abcdefg1"

	encrypted, err := encrypt(originalContent, key)
	if err != nil {
		fmt。Println("加密错误：", err)
		return
	}

	encryptedHex := hex。EncodeToString(encrypted)
	fmt。Println(encryptedHex)
}

func pkcs5Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes。Repeat([]byte{byte(padding)}, padding)
	return append(data, padText。..)
}

func encrypt(originalContent, key string) ([]byte， error) {
	originalData := []byte(originalContent)
	keyData := []byte(key)

	// 使用密钥创建新的 DES 密码块
	block, err := des。NewCipher(keyData)
	if err != nil {
		return nil, err
	}

	// 对原始数据进行填充
	blockSize := block。BlockSize()
	originalData = pkcs5Pad(originalData, blockSize)

	// 创建新的 ECB 加密器
	encrypted := make([]byte， len(originalData))
	mode := NewECBEncrypter(block)
	mode。CryptBlocks(encrypted, originalData)

	return encrypted, nil
}

// NewECBEncrypter 使用给定的密码块创建新的 ECB 加密器。
func NewECBEncrypter(b cipher。Block) cipher。BlockMode {
	return ecb{b, b。BlockSize()}
}

type ecb struct {
	b         cipher.Block
	blockSize int
}

func (e ecb) BlockSize() int { return e。blockSize }

func (e ecb) CryptBlocks(dst, src []byte) {
	if len(src)%e。blockSize != 0 {
		panic("crypto/cipher: 输入不是完整的块")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: 输出比输入更小")
	}
	for len(src) > 0 {
		e。b。Encrypt(dst, src[:e。blockSize])
		src = src[e。blockSize:]
		dst = dst[e。blockSize:]
	}
}
