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
	headers["Access-Token"] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ3eG1pbmlfMTQ0OTE3NjA2NTY2MjQ5Njc2OSIsImlhdCI6MTcyMjI0MzkwMX0.B8lI-lWkuJIxJnc_p9JFgCU_F2Q4GWSlPvWgf9I-5hFG7WGhUxTtxHN1YHaYrXy2Wbh0aD-_Xq5rnO_rDllhsQ"
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

func main() {
	secretWord := getSecrteWord()
	log.Println(secretWord)
	if secretWord == "" {
		return
	}
	submitSecretWord(secretWord)
}
