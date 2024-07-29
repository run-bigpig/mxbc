package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
)

var (
	headers = map[string]interface{}{
		"Accept":             "application/json, text/plain, */*",
		"Origin":             "https://mxsa-h5.mxbc.net",
		"Pragma":             "no-cache",
		"Referer":            "https://mxsa-h5.mxbc.net/",
		"User-Agent":         "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36",
		"sec-ch-ua":          "\"Not)A;Brand\";v=\"99\", \"Google Chrome\";v=\"127\", \"Chromium\";v=\"127\"",
		"sec-ch-ua-mobile":   "?1",
		"sec-ch-ua-platform": "\"Android\"",
	}
	salt = "c274bac6493544b89d9c4f9d8d542b84"

	accessToken = "" //访问token 自行抓包
)

func genSign(jsonData map[string]interface{}, salt string) string {
	// 将jsonData的keys排序
	keys := make([]string, 0, len(jsonData))
	for key := range jsonData {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	// 根据排序后的key顺序拼接字符串
	var dataStr strings.Builder
	for i, key := range keys {
		if i > 0 {
			dataStr.WriteString("&")
		}
		dataStr.WriteString(fmt.Sprintf("%s=%v", key, jsonData[key]))
	}
	dataStr.WriteString(salt)

	// 进行md5加密
	hash := md5.Sum([]byte(dataStr.String()))
	return hex.EncodeToString(hash[:])
}

// 获取当场口令
func getSecrteWord() string {
	url := "https://mxsa.mxbc.net/api/v1/h5/marketing/secretword/info"
	jsonData := map[string]interface{}{
		"marketingId": "1816854086004391938",
		"s":           2,
		"stamp":       time.Now().UnixMilli(),
	}
	jsonData["sign"] = genSign(jsonData, salt)
	resp, err := Do(http.MethodGet, url, jsonData, headers)
	if err != nil {
		fmt.Println("Error making request:", err)
		return ""
	}
	var response map[string]interface{}
	if err := json.Unmarshal(resp, &response); err != nil {
		fmt.Println("Error unmarshalling JSON:", err)
		return ""
	}
	if data, ok := response["data"].(map[string]interface{}); ok {
		return strings.ReplaceAll(data["hintWord"].(string), "本场口令：", "")
	}
	return ""
}

// 提交当场口令
func submitSecretWord(secretWord string) {
	url := "https://mxsa.mxbc.net/api/v1/h5/marketing/secretword/confirm"
	jsonData := map[string]interface{}{
		"marketingId": "1816854086004391938",
		"round":       "18:00",
		"secretword":  secretWord,
		"s":           2,
		"stamp":       time.Now().UnixMilli(),
	}
	jsonData["sign"] = genSign(jsonData, salt)
	headers["Content-Type"] = "application/json;charset=UTF-8"
	headers["Access-Token"] = accessToken
	resp, err := Do(http.MethodPost, url, jsonData, headers)
	if err != nil {
		fmt.Println("Error making request:", err)
		return
	}
	log.Println(string(resp))
}

func Do(method, url string, data, header map[string]interface{}) ([]byte, error) {
	var (
		client = &http.Client{}
		r      = &http.Request{}
	)
	switch method {
	case http.MethodGet:
		var params string
		for key, value := range data {
			params += fmt.Sprintf("%s=%v&", key, value)
		}
		url += "?" + params[:len(params)-1]
		request, err := http.NewRequest(method, url, nil)
		if err != nil {
			fmt.Println("Error creating request:", err)
			return nil, err
		}
		r = request
	case http.MethodPost:
		jsonBytes, err := json.Marshal(data)
		if err != nil {
			fmt.Println("Error marshalling JSON:", err)
			return nil, err
		}
		request, err := http.NewRequest(method, url, strings.NewReader(string(jsonBytes)))
		if err != nil {
			fmt.Println("Error creating request:", err)
			return nil, err
		}
		r = request
	default:
		fmt.Println("Unsupported HTTP method:", method)
		return nil, errors.New("Unsupported HTTP method")
	}
	for key, value := range header {
		r.Header.Add(key, fmt.Sprintf("%v", value))
	}
	resp, err := client.Do(r)
	if err != nil {
		fmt.Println("Error making request:", err)
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Println("Error making request:", resp.Status)
		return nil, errors.New("Error making request")
	}
	return io.ReadAll(resp.Body)
}

func runTask() {
	secretWord := getSecrteWord()
	fmt.Println("当场口令:", secretWord)
	if secretWord == "" {
		fmt.Println("未获取到当场口令")
		return
	}
	submitSecretWord(secretWord)
	fmt.Println("当前任务执行时间:", time.Now().Format("2006-01-02 15:04:05"))
}

func main() {
	fmt.Println("开始执行任务")
	// 创建一个每分钟触发一次的Ticker
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			// 检查当前时间是否在11:00到20:59之间的整点
			if now.Minute() == 0 && now.Hour() >= 11 && now.Hour() <= 20 {
				//执行20次
				for i := 0; i < 20; i++ {
					runTask()
				}
			}
		}
	}
}
