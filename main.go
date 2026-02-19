package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	jwtToken      string
	jwtExpiration int64
	jwtMu         sync.Mutex

	hfToken     string
	hfSpaceName string
	hfSpaceUser string
	targetHost  string
	listenAddr  string
)

type jwtResponse struct {
	Token string `json:"token"`
}

func getJwtToken() (string, error) {
	jwtMu.Lock()
	defer jwtMu.Unlock()

	now := time.Now().Unix()
	if jwtToken != "" && jwtExpiration > now+60 {
		return jwtToken, nil
	}

	apiURL := fmt.Sprintf("https://huggingface.co/api/spaces/%s/%s/jwt", hfSpaceUser, hfSpaceName)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+hfToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch JWT token: %s", resp.Status)
	}

	var result jwtResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	jwtToken = result.Token

	// 解析 JWT 过期时间
	parts := strings.Split(jwtToken, ".")
	if len(parts) == 3 {
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err == nil {
			var claims struct {
				Exp int64 `json:"exp"`
			}
			if json.Unmarshal(payload, &claims) == nil && claims.Exp > 0 {
				jwtExpiration = claims.Exp
				return jwtToken, nil
			}
		}
	}
	jwtExpiration = now + 3600
	return jwtToken, nil
}

// hopHeaders 不应被代理转发
var hopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	token, err := getJwtToken()
	if err != nil {
		http.Error(w, "Proxy Error: "+err.Error(), http.StatusBadGateway)
		return
	}

	// 构建目标 URL
	target := &url.URL{
		Scheme:   "https",
		Host:     targetHost,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}

	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), r.Body)
	if err != nil {
		http.Error(w, "Proxy Error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 复制请求头
	for k, vv := range r.Header {
		for _, v := range vv {
			proxyReq.Header.Add(k, v)
		}
	}
	for _, h := range hopHeaders {
		proxyReq.Header.Del(h)
	}

	// 注入 JWT Cookie
	existing := r.Header.Get("Cookie")
	spaceCookie := "spaces-jwt=" + token
	if existing != "" {
		proxyReq.Header.Set("Cookie", existing+"; "+spaceCookie)
	} else {
		proxyReq.Header.Set("Cookie", spaceCookie)
	}

	proxyReq.Header.Set("Host", targetHost)
	proxyReq.Host = targetHost

	// 转发客户端真实 IP
	clientIP := r.Header.Get("X-Forwarded-For")
	if clientIP == "" {
		clientIP = strings.Split(r.RemoteAddr, ":")[0]
	}
	if clientIP != "" {
		proxyReq.Header.Set("X-Forwarded-For", clientIP)
		proxyReq.Header.Set("X-Real-IP", clientIP)
	}

	// 禁止自动重定向
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, "Proxy Error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 复制响应头
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	// 改写重定向 Location
	if loc := resp.Header.Get("Location"); loc != "" {
		originalHost := r.Host
		rewritten := strings.ReplaceAll(loc, targetHost, originalHost)
		w.Header().Set("Location", rewritten)
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func main() {
	hfToken = os.Getenv("HF_TOKEN")
	hfSpaceName = os.Getenv("HF_SPACE_NAME")
	hfSpaceUser = os.Getenv("HF_SPACE_USER")
	listenAddr = os.Getenv("LISTEN_ADDR")

	if hfToken == "" || hfSpaceName == "" || hfSpaceUser == "" {
		log.Fatal("HF_TOKEN, HF_SPACE_NAME, HF_SPACE_USER are required")
	}
	if listenAddr == "" {
		listenAddr = ":8080"
	}

	targetHost = fmt.Sprintf("%s-%s.hf.space", hfSpaceUser, hfSpaceName)

	log.Printf("FaceProxy listening on %s -> %s", listenAddr, targetHost)
	log.Fatal(http.ListenAndServe(listenAddr, http.HandlerFunc(proxyHandler)))
}
