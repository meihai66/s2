package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	//"net/url"
	"runtime"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	address    common.Address
	PrivateKey string
	Prefix     string
	Challenge  string
)

func init() {
	Challenge = "72424e4200000000000000000000000000000000000000000000000000000000"

	fmt.Print("PrivateKey：")
	_, err := fmt.Scanln(&PrivateKey)
	if err != nil {
		return
	}
	if len(PrivateKey) == 64 {
		PrivateKey = "0x" + PrivateKey
	}
	fmt.Print("Difficulty：")
	_, err = fmt.Scanln(&Prefix)
	if err != nil {
		return
	}
}

func main() {
	bytePrivyKey, err := hexutil.Decode(PrivateKey)
	if err != nil {
		panic(err)
	}
	prv, _ := btcec.PrivKeyFromBytes(bytePrivyKey)
	address = crypto.PubkeyToAddress(*prv.PubKey().ToECDSA())

	for i := 0; i < runtime.NumCPU(); i++ {
		go func() {
			for {
				makeTx()
			}
		}()
	}
	select {}

}

func sendTX(body string) {
	// 设置代理地址
	//proxyAddress := "http://127.0.0.1:10900"

	// 创建一个使用代理的Transport
	//proxyURL, err := url.Parse(proxyAddress)
	//if err != nil {
	//	fmt.Println("解析代理地址出错:", err)
	//	return
	//}
	// 创建一个使用代理的Transport
	//transport := &http.Transport{
	//	Proxy: http.ProxyURL(proxyURL),
	//}
	client := &http.Client{
	//	Transport: transport,
	}

	var data = strings.NewReader(body)
	req, err := http.NewRequest("POST", "https://ec2-18-217-135-255.us-east-2.compute.amazonaws.com/validate", data)
	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("origin", "https://bnb.reth.cc")
	req.Header.Set("referer", "https://bnb.reth.cc/")
	req.Header.Set("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Println(err)
			return
		}
	}(resp.Body)

	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	bodyString := string(bodyText)
	containsValidateSuccess := strings.Contains(bodyString, "validate success!")
	if containsValidateSuccess {
		fmt.Print("MINT OK")
	} else {
		fmt.Println(err)
	}

}

func makeTx() {
	randomValue := make([]byte, 32)
	_, err := rand.Read(randomValue)
	if err != nil {
		fmt.Println(err)
		return
	}

	potentialSolution := hex.EncodeToString(randomValue)
	address64 := fmt.Sprintf("%064s", strings.ToLower(address.Hex()[2:]))
	dataTemps := fmt.Sprintf(`%s%s%s`, potentialSolution, Challenge, address64)

	dataBytes, err := hex.DecodeString(dataTemps)
	if err != nil {
		fmt.Println(err)
		return
	}

	hashedSolutionBytes := crypto.Keccak256(dataBytes)
	hashedSolution := fmt.Sprintf("0x%s", hex.EncodeToString(hashedSolutionBytes))

	if strings.HasPrefix(hashedSolution, Prefix) {
		fmt.Println("Solution", hashedSolution)
		body := fmt.Sprintf(`{"solution": "0x%s", "challenge": "0x%s", "address": "%s", "difficulty": "%s", "tick": "%s"}`, potentialSolution, Challenge, strings.ToLower(address.String()), Prefix, "rBNB")
		sendTX(body)
	}
}
