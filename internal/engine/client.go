package engine

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sc-checker-go/internal/config"
	"sync"
	"time"
)

type HTTPClient struct {
	client     *http.Client
	transport  *http.Transport
	proxyURL   *url.URL
	userAgents []string
	uaMu       sync.Mutex
	uaIdx      int
	HookFn     func(hook string, reqData map[string]any)
}

func NewHTTPClient(proxy string, timeout int) (*HTTPClient, error) {
	return NewHTTPClientWithUA(proxy, timeout, nil)
}

func NewHTTPClientWithUA(proxy string, timeout int, userAgents []string) (*HTTPClient, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(timeout) * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
	}

	c := &HTTPClient{
		transport:  transport,
		userAgents: userAgents,
	}

	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		c.proxyURL = proxyURL
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	jar, _ := cookiejar.New(nil)
	c.client = &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Second,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	return c, nil
}

func (c *HTTPClient) SetUserAgents(agents []string) {
	c.uaMu.Lock()
	defer c.uaMu.Unlock()
	c.userAgents = agents
	c.uaIdx = 0
}

func (c *HTTPClient) nextUserAgent() string {
	c.uaMu.Lock()
	defer c.uaMu.Unlock()

	if len(c.userAgents) == 0 {
		return config.UserAgent
	}

	if c.uaIdx >= len(c.userAgents) {
		c.uaIdx = 0
	}
	ua := c.userAgents[c.uaIdx]
	c.uaIdx++

	if c.uaIdx%8 == 0 {
		rng := rand.New(rand.NewSource(time.Now().UnixNano()))
		c.uaIdx = rng.Intn(len(c.userAgents))
	}

	return ua
}

func (c *HTTPClient) Get(u string, headers map[string]string) (*http.Response, time.Duration, error) {
	return c.do("GET", u, headers, nil)
}

func (c *HTTPClient) Post(u string, headers map[string]string, body string) (*http.Response, time.Duration, error) {
	return c.do("POST", u, headers, []byte(body))
}

func (c *HTTPClient) do(method, u string, headers map[string]string, body []byte) (*http.Response, time.Duration, error) {
	if c.HookFn != nil {
		c.HookFn("on_before_request", map[string]any{
			"method":  method,
			"url":     u,
			"headers": headers,
		})
	}

	var req *http.Request
	var err error

	if method == "POST" && body != nil {
		req, err = http.NewRequest(method, u, bytes.NewReader(body))
	} else {
		req, err = http.NewRequest(method, u, nil)
	}
	if err != nil {
		return nil, 0, err
	}

	req.Header.Set("User-Agent", c.nextUserAgent())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := c.client.Do(req)
	elapsed := time.Since(start)

	if c.HookFn != nil {
		respData := map[string]any{
			"method": method,
			"url":    u,
			"status": 0,
		}
		if resp != nil {
			respData["status"] = resp.StatusCode
		}
		if err != nil {
			respData["error"] = err.Error()
		}
		c.HookFn("on_request", respData)
	}

	return resp, elapsed, err
}

func (c *HTTPClient) Close() {
	c.client.CloseIdleConnections()
}

type ConcurrentClient struct {
	pool       []*HTTPClient
	poolSize   int
	userAgents []string
}

func NewConcurrentClient(proxy string, timeout, poolSize int) (*ConcurrentClient, error) {
	cc := &ConcurrentClient{
		pool:     make([]*HTTPClient, poolSize),
		poolSize: poolSize,
	}
	for i := 0; i < poolSize; i++ {
		client, err := NewHTTPClient(proxy, timeout)
		if err != nil {
			return nil, err
		}
		cc.pool[i] = client
	}
	return cc, nil
}

func (cc *ConcurrentClient) SetUserAgents(agents []string) {
	cc.userAgents = agents
	for _, c := range cc.pool {
		c.SetUserAgents(agents)
	}
}

func (cc *ConcurrentClient) SetHookFn(fn func(string, map[string]any)) {
	for _, c := range cc.pool {
		c.HookFn = fn
	}
}

func (cc *ConcurrentClient) Get(idx int, u string, headers map[string]string) (*http.Response, time.Duration, error) {
	return cc.pool[idx%cc.poolSize].Get(u, headers)
}

func (cc *ConcurrentClient) Close() {
	for _, c := range cc.pool {
		c.Close()
	}
}
