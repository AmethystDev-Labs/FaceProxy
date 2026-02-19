package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
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

	enableWarp    bool
	socksAddr     = "127.0.0.1:40000"
	httpTransport *http.Transport
)

type jwtResponse struct {
	Token string `json:"token"`
}

// socks5Dial 通过 SOCKS5 代理建立 TCP 连接（无外部依赖）
func socks5Dial(proxyAddr, targetAddr string) (net.Conn, error) {
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, err
	}

	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// 握手：VER=5, NMETHODS=1, METHOD=0(无认证)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, err
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		conn.Close()
		return nil, err
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5: unsupported auth method %d", buf[1])
	}

	// CONNECT 请求
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	// 读取响应
	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5: connect failed with code %d", resp[1])
	}
	// 消费剩余的绑定地址
	switch resp[3] {
	case 0x01:
		io.ReadFull(conn, make([]byte, 4+2))
	case 0x03:
		lenBuf := make([]byte, 1)
		io.ReadFull(conn, lenBuf)
		io.ReadFull(conn, make([]byte, int(lenBuf[0])+2))
	case 0x04:
		io.ReadFull(conn, make([]byte, 16+2))
	}
	return conn, nil
}

// dialTLSBackend 建立到后端的 TLS 连接，可选走 SOCKS5
func dialTLSBackend(host string) (net.Conn, error) {
	addr := host + ":443"
	var rawConn net.Conn
	var err error
	if enableWarp {
		rawConn, err = socks5Dial(socksAddr, addr)
	} else {
		rawConn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(rawConn, &tls.Config{ServerName: host})
	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
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

	resp, err := (&http.Client{Transport: httpTransport}).Do(req)
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

// hopHeaders 不应被代理转发（普通 HTTP 请求）
var hopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func isWebSocket(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	token, err := getJwtToken()
	if err != nil {
		http.Error(w, "Proxy Error: "+err.Error(), http.StatusBadGateway)
		return
	}

	// 劫持客户端连接
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "WebSocket hijack not supported", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		http.Error(w, "Hijack failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// TLS 连接到后端（可选走 WARP）
	backendConn, err := dialTLSBackend(targetHost)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer backendConn.Close()

	// 构建升级请求
	reqURL := r.URL.Path
	if r.URL.RawQuery != "" {
		reqURL += "?" + r.URL.RawQuery
	}
	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", r.Method, reqURL))
	buf.WriteString(fmt.Sprintf("Host: %s\r\n", targetHost))

	// 复制原始请求头（保留 WebSocket 相关头）
	for k, vv := range r.Header {
		kl := strings.ToLower(k)
		if kl == "host" {
			continue
		}
		for _, v := range vv {
			buf.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}
	}

	// 注入 JWT Cookie
	existing := r.Header.Get("Cookie")
	spaceCookie := "spaces-jwt=" + token
	if existing != "" {
		buf.WriteString(fmt.Sprintf("Cookie: %s; %s\r\n", existing, spaceCookie))
	} else {
		buf.WriteString(fmt.Sprintf("Cookie: %s\r\n", spaceCookie))
	}

	// 转发客户端真实 IP
	clientIP := r.Header.Get("X-Forwarded-For")
	if clientIP == "" {
		clientIP, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	if clientIP != "" {
		buf.WriteString(fmt.Sprintf("X-Forwarded-For: %s\r\n", clientIP))
		buf.WriteString(fmt.Sprintf("X-Real-IP: %s\r\n", clientIP))
	}

	buf.WriteString("\r\n")

	// 发送升级请求到后端
	if _, err := backendConn.Write([]byte(buf.String())); err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	// 读取后端响应并转发给客户端
	backendBuf := bufio.NewReader(backendConn)
	resp, err := http.ReadResponse(backendBuf, r)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	// 将后端响应原样写回客户端
	var respBuf strings.Builder
	respBuf.WriteString(fmt.Sprintf("HTTP/1.1 %s\r\n", resp.Status))
	for k, vv := range resp.Header {
		for _, v := range vv {
			respBuf.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}
	}
	respBuf.WriteString("\r\n")
	clientConn.Write([]byte(respBuf.String()))

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return
	}

	// 双向转发数据
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(backendConn, clientBuf)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, backendBuf)
		done <- struct{}{}
	}()
	<-done
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	if isWebSocket(r) {
		handleWebSocket(w, r)
		return
	}

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
		Transport: httpTransport,
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
	enableWarp = os.Getenv("ENABLE_AUTOWARP") == "true"
	listenAddr = os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		if port := os.Getenv("PORT"); port != "" {
			listenAddr = ":" + port
		}
	}

	if hfToken == "" || hfSpaceName == "" || hfSpaceUser == "" {
		log.Fatal("HF_TOKEN, HF_SPACE_NAME, HF_SPACE_USER are required")
	}
	if listenAddr == "" {
		listenAddr = ":8080"
	}

	// 初始化 HTTP Transport
	httpTransport = &http.Transport{}
	if enableWarp {
		proxyURL, _ := url.Parse("socks5://" + socksAddr)
		httpTransport.Proxy = http.ProxyURL(proxyURL)
		log.Printf("WARP SOCKS5 proxy enabled via %s", socksAddr)
	}

	targetHost = fmt.Sprintf("%s-%s.hf.space", hfSpaceUser, hfSpaceName)

	log.Printf("FaceProxy listening on %s -> %s", listenAddr, targetHost)
	log.Fatal(http.ListenAndServe(listenAddr, http.HandlerFunc(proxyHandler)))
}
