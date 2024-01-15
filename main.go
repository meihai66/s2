package main

import (
	crypto_rand "crypto/rand"
	math_rand "math/rand"

	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	//PrivateKey string
	//Difficulty= "0x9999"
	//Challenge = "72424e4200000000000000000000000000000000000000000000000000000000"
	Counter    int64
	CounterMax int64
	wg         sync.WaitGroup
)

type APIData struct {
	Challenge    string `json:"Challenge"`
	Difficulty   string `json:"Difficulty"`
	PrivateKey   string `json:"PrivateKey"`
	ProxyAddress string `json:"ProxyAddress"`
}

func fetchData(apiURL string) (APIData, error) {
	var data APIData

	for {
		// 发送 HTTP 请求
		response, err := http.Get(apiURL)
		if err != nil {
			fmt.Println("Get:", err)
			time.Sleep(2 * time.Second) // 休息2秒
			continue
		}
		defer response.Body.Close()

		// 读取响应体
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			fmt.Println("ReadAll:", err)
			time.Sleep(2 * time.Second) // 休息2秒
			continue
		}

		// 解析 JSON 数据
		err = json.Unmarshal(body, &data)
		if err != nil {
			fmt.Println("JSON:", err)
			time.Sleep(2 * time.Second) // 休息2秒
			continue
		}

		return data, nil
	}
}
func main() {
	math_rand.Seed(time.Now().UnixNano())

	
	var address common.Address
	fmt.Println("fetchData",runtime.NumCPU())
	for {
		data, err := fetchData("http://134.175.55.154:13333/difficulty")
		if err != nil {
			fmt.Println("fetchData:", err)
			return
		}
                CounterMax = int64(math_rand.Intn(801) + 4000) //4000-4800
		bytePrivyKey, err := hexutil.Decode(data.PrivateKey)
		if err != nil {
			panic(err)
		}
		prv, _ := btcec.PrivKeyFromBytes(bytePrivyKey)
		address = crypto.PubkeyToAddress(*prv.PubKey().ToECDSA())
		fmt.Println("address",address,CounterMax)

		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				for {
					if Counter >= CounterMax {
						defer wg.Done()
						break
					}
					makeTx(address, data.Challenge, data.Difficulty, data.ProxyAddress)
				}
			}()
		}

		wg.Wait()
		fmt.Println("MINT END", Counter)
	}

}

func sendTX(address string, body string, proxyAddress string) {
	//proxyAddress "http://127.0.0.1:10900"
	// 创建一个使用代理的Transport
	var transport http.RoundTripper

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	if proxyAddress != "" {
		proxyURL, err := url.Parse(proxyAddress)
		if err != nil {
			fmt.Println("proxyAddress:", err)
			return
		}
		transport = &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: tlsConfig,
		}
	} else {
		transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}

	client := &http.Client{
		Transport: transport,
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
		atomic.AddInt64(&Counter, 1)
		fmt.Println("MINT OK", Counter, CounterMax, address)
	} else {
		//fmt.Println(err)
	}

}

func makeTx(address common.Address, Challenge string, Difficulty string, proxyAddress string) {
	randomValue := make([]byte, 32)
	_, err := crypto_rand.Read(randomValue)
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

	if strings.HasPrefix(hashedSolution, Difficulty) {
		//fmt.Println("Solution", hashedSolution)
		body := fmt.Sprintf(`{"solution": "0x%s", "challenge": "0x%s", "address": "%s", "difficulty": "%s", "tick": "%s"}`, potentialSolution, Challenge, strings.ToLower(address.String()), Difficulty, "rBNB")
		sendTX(strings.ToLower(address.String()), body, proxyAddress)
	}
}
