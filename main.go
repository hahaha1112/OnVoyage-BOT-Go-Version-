package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

const baseAPI = "https://onvoyage-backend-954067898723.us-central1.run.app"

const (
	clrReset        = "\x1b[0m"
	clrPurpleDeep   = "\x1b[38;2;109;40;217m"  // #6D28D9
	clrPurpleBright = "\x1b[38;2;168;85;247m"  // #A855F7
	clrMagentaNeon  = "\x1b[38;2;232;121;249m" // #E879F9
	clrCyanNeon     = "\x1b[38;2;34;211;238m"  // #22D3EE
	clrPinkError    = "\x1b[38;2;244;114;182m" // #F472B6
	clrWhite        = "\x1b[38;2;245;245;255m" // #F5F5FF
)

var noColor = os.Getenv("NO_COLOR") != ""

func colorize(code, text string) string {
	if noColor {
		return text
	}
	return code + text + clrReset
}

func cCyan(text string) string    { return colorize(clrPurpleBright, text) }
func cGreen(text string) string   { return colorize(clrMagentaNeon, text) }
func cYellow(text string) string  { return colorize(clrCyanNeon, text) }
func cRed(text string) string     { return colorize(clrPinkError, text) }
func cBlue(text string) string    { return colorize(clrPurpleDeep, text) }
func cMagenta(text string) string { return colorize(clrMagentaNeon, text) }
func cWhite(text string) string   { return colorize(clrWhite, text) }

func gradient(text string, colors []string) string {
	if noColor || len(colors) == 0 {
		return text
	}
	runes := []rune(text)
	var b strings.Builder
	for i, ch := range runes {
		color := colors[i%len(colors)]
		b.WriteString(color)
		b.WriteRune(ch)
	}
	b.WriteString(clrReset)
	return b.String()
}

type Bot struct {
	BaseAPI        string
	UseProxy       bool
	RotateProxy    bool
	Headers        map[string]map[string]string
	Proxies        []string
	ProxyIndex     int
	AccountProxies map[string]string
	UserAgents     []string
	Rand           *rand.Rand
	Location       *time.Location
}

func NewBot() *Bot {
	loc, _ := time.LoadLocation("Asia/Jakarta")
	return &Bot{
		BaseAPI:        baseAPI,
		UseProxy:       false,
		RotateProxy:    false,
		Headers:        map[string]map[string]string{},
		Proxies:        []string{},
		ProxyIndex:     0,
		AccountProxies: map[string]string{},
		UserAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
			"Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/117.0.0.0",
		},
		Rand:     rand.New(rand.NewSource(time.Now().UnixNano())),
		Location: loc,
	}
}

func (b *Bot) clearTerminal() {
	if runtime.GOOS == "windows" {
		_ = exec.Command("cmd", "/c", "cls").Run()
		return
	}
	_ = exec.Command("clear").Run()
}

func (b *Bot) log(message string) {
	ts := time.Now().In(b.Location).Format("01/02/06 15:04:05 MST")
	if noColor {
		fmt.Printf("[ %s ] | %s\n", ts, message)
		return
	}
	fmt.Printf("%s[ %s ]%s %s| %s%s\n", clrPurpleBright, ts, clrReset, clrWhite, message, clrReset)
}

func (b *Bot) welcome() {
	fmt.Println("")
	fmt.Println("        " + cGreen("OnVoyage") + " " + cBlue("Auto BOT"))
	fmt.Println("            " + cGreen("Rey?") + " " + cYellow("<INI WATERMARK>"))
	fmt.Println("")
}

func (b *Bot) formatSeconds(seconds int) string {
	h := seconds / 3600
	m := (seconds % 3600) / 60
	s := seconds % 60
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

func (b *Bot) loadTokens() []string {
	filename := "tokens.txt"
	tokens, err := readNonEmptyLines(filename)
	if err != nil && os.IsNotExist(err) {
		alt := filepath.Join("..", filename)
		tokens, err = readNonEmptyLines(alt)
	}
	if err != nil {
		fmt.Printf("%s%v%s\n", cRed("Failed To Load Tokens: "), err, clrReset)
		return nil
	}
	return tokens
}

func (b *Bot) loadProxies() {
	filename := "proxy.txt"
	proxies, err := readNonEmptyLines(filename)
	if err != nil && os.IsNotExist(err) {
		alt := filepath.Join("..", filename)
		proxies, err = readNonEmptyLines(alt)
	}
	if err != nil {
		if os.IsNotExist(err) {
			b.log(cRed(fmt.Sprintf("File %s Not Found.", filename)))
			return
		}
		b.log(cRed(fmt.Sprintf("Failed To Load Proxies: %v", err)))
		return
	}
	if len(proxies) == 0 {
		b.log(cRed("No Proxies Found."))
		return
	}
	b.Proxies = proxies
	b.log(cGreen("Proxies Total  : ") + cWhite(fmt.Sprintf("%d", len(b.Proxies))))
}

func (b *Bot) checkProxySchemes(p string) string {
	schemes := []string{"http://", "https://", "socks4://", "socks5://"}
	for _, s := range schemes {
		if strings.HasPrefix(p, s) {
			return p
		}
	}
	return "http://" + p
}

func (b *Bot) getNextProxyForAccount(account string) string {
	if _, ok := b.AccountProxies[account]; !ok {
		if len(b.Proxies) == 0 {
			return ""
		}
		proxyURL := b.checkProxySchemes(b.Proxies[b.ProxyIndex])
		b.AccountProxies[account] = proxyURL
		b.ProxyIndex = (b.ProxyIndex + 1) % len(b.Proxies)
	}
	return b.AccountProxies[account]
}

func (b *Bot) rotateProxyForAccount(account string) string {
	if len(b.Proxies) == 0 {
		return ""
	}
	proxyURL := b.checkProxySchemes(b.Proxies[b.ProxyIndex])
	b.AccountProxies[account] = proxyURL
	b.ProxyIndex = (b.ProxyIndex + 1) % len(b.Proxies)
	return proxyURL
}

func displayProxy(proxyURL string) string {
	if proxyURL == "" {
		return "No Proxy"
	}
	if u, err := url.Parse(proxyURL); err == nil && u.Host != "" {
		return u.Host
	}
	s := proxyURL
	for _, scheme := range []string{"http://", "https://", "socks4://", "socks5://"} {
		if strings.HasPrefix(s, scheme) {
			s = strings.TrimPrefix(s, scheme)
			break
		}
	}
	if at := strings.LastIndex(s, "@"); at != -1 {
		s = s[at+1:]
	}
	return s
}

func (b *Bot) decodeJWTExp(token string) (int64, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0, fmt.Errorf("invalid token format")
	}
	payload := parts[1]
	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return 0, err
	}
	var parsed map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&parsed); err != nil {
		return 0, err
	}
	exp, ok := toInt64(parsed["exp"])
	if !ok {
		return 0, fmt.Errorf("exp not found")
	}
	return exp, nil
}

func (b *Bot) initializeHeaders(token string) http.Header {
	if _, ok := b.Headers[token]; !ok {
		ua := b.UserAgents[b.Rand.Intn(len(b.UserAgents))]
		b.Headers[token] = map[string]string{
			"Accept":          "application/json, text/plain, */*",
			"Accept-Encoding": "gzip, deflate, br",
			"Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
			"Authorization":   "Bearer " + token,
			"Cache-Control":   "no-cache",
			"Origin":          "https://app.onvoyage.ai",
			"Pragma":          "no-cache",
			"Referer":         "https://app.onvoyage.ai/",
			"Sec-Fetch-Dest":  "empty",
			"Sec-Fetch-Mode":  "cors",
			"Sec-Fetch-Site":  "cross-site",
			"User-Agent":      ua,
		}
	}
	h := http.Header{}
	for k, v := range b.Headers[token] {
		h.Set(k, v)
	}
	return h
}

func (b *Bot) printQuestion() {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println(cWhite("1. Run With Proxy"))
		fmt.Println(cWhite("2. Run Without Proxy"))
		fmt.Print(cBlue("Choose [1/2] -> "))
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		choice, err := strconv.Atoi(line)
		if err != nil {
			fmt.Println(cRed("Invalid input. Enter a number (1 or 2)."))
			continue
		}
		if choice == 1 || choice == 2 {
			if choice == 1 {
				fmt.Println(cGreen("Run With Proxy Selected."))
				b.UseProxy = true
			} else {
				fmt.Println(cGreen("Run Without Proxy Selected."))
				b.UseProxy = false
			}
			break
		}
		fmt.Println(cRed("Please enter either 1 or 2."))
	}

	if b.UseProxy {
		for {
			fmt.Print(cBlue("Rotate Invalid Proxy? [y/n] -> "))
			line, _ := reader.ReadString('\n')
			line = strings.TrimSpace(line)
			if line == "y" || line == "n" {
				b.RotateProxy = (line == "y")
				break
			}
			fmt.Println(cRed("Invalid input. Enter 'y' or 'n'."))
		}
	}
}

type socks4Dialer struct {
	proxyAddr string
	user      string
	timeout   time.Duration
}

func (d *socks4Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var nd net.Dialer
	nd.Timeout = d.timeout
	conn, err := nd.DialContext(ctx, "tcp", d.proxyAddr)
	if err != nil {
		return nil, err
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		conn.Close()
		return nil, err
	}

	ip := net.ParseIP(host)
	ip4 := net.IP(nil)
	useSocks4A := false
	if ip != nil {
		ip4 = ip.To4()
	}
	if ip4 == nil {
		useSocks4A = true
		ip4 = net.IPv4(0, 0, 0, 1)
	}

	var buf bytes.Buffer
	buf.WriteByte(0x04)
	buf.WriteByte(0x01)
	buf.WriteByte(byte(port >> 8))
	buf.WriteByte(byte(port))
	buf.Write(ip4)
	if d.user != "" {
		buf.WriteString(d.user)
	}
	buf.WriteByte(0x00)
	if useSocks4A {
		buf.WriteString(host)
		buf.WriteByte(0x00)
	}

	_ = conn.SetDeadline(time.Now().Add(d.timeout))
	if _, err := conn.Write(buf.Bytes()); err != nil {
		conn.Close()
		return nil, err
	}

	resp := make([]byte, 8)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[1] != 0x5a {
		conn.Close()
		return nil, fmt.Errorf("socks4 connect failed, code 0x%02x", resp[1])
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func (b *Bot) buildHTTPClient(proxyURL string, timeout time.Duration) (*http.Client, error) {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil, err
		}
		switch u.Scheme {
		case "http", "https":
			tr.Proxy = http.ProxyURL(u)
		case "socks5":
			var auth *proxy.Auth
			if u.User != nil {
				pass, _ := u.User.Password()
				auth = &proxy.Auth{
					User:     u.User.Username(),
					Password: pass,
				}
			}
			d, err := proxy.SOCKS5("tcp", u.Host, auth, proxy.Direct)
			if err != nil {
				return nil, err
			}
			tr.Proxy = nil
			tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return d.Dial(network, addr)
			}
		case "socks4":
			user := ""
			if u.User != nil {
				user = u.User.Username()
			}
			d := &socks4Dialer{proxyAddr: u.Host, user: user, timeout: 30 * time.Second}
			tr.Proxy = nil
			tr.DialContext = d.DialContext
		default:
			return nil, fmt.Errorf("unsupported proxy scheme: %s", u.Scheme)
		}
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}, nil
}

func (b *Bot) checkConnection(proxyURL string) bool {
	url := "https://api.ipify.org?format=json"
	client, err := b.buildHTTPClient(proxyURL, 30*time.Second)
	if err != nil {
		b.log(cCyan("Status  :") + " " + cRed("Connection Not 200 OK") + " " + cMagenta("-") + " " + cYellow(err.Error()))
		return false
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		b.log(cCyan("Status  :") + " " + cRed("Connection Not 200 OK") + " " + cMagenta("-") + " " + cYellow(err.Error()))
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		b.log(cCyan("Status  :") + " " + cRed("Connection Not 200 OK") + " " + cMagenta("-") + " " + cYellow(err.Error()))
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		b.log(cCyan("Status  :") + " " + cRed("Connection Not 200 OK") + " " + cMagenta("-") + " " + cYellow(fmt.Sprintf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))))
		return false
	}
	return true
}

func (b *Bot) requestJSON(method, url string, headers http.Header, proxyURL string, timeout time.Duration) (map[string]interface{}, error) {
	client, err := b.buildHTTPClient(proxyURL, timeout)
	if err != nil {
		return nil, err
	}
	var body io.Reader
	if method == "POST" {
		body = strings.NewReader("")
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header = headers
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	var payload map[string]interface{}
	if err := dec.Decode(&payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func (b *Bot) userProfile(token string, proxyURL string, retries int) map[string]interface{} {
	url := b.BaseAPI + "/api/v1/user/profile"
	for attempt := 0; attempt < retries; attempt++ {
		headers := b.initializeHeaders(token)
		resp, err := b.requestJSON("GET", url, headers, proxyURL, 60*time.Second)
		if err == nil {
			return resp
		}
		if attempt < retries-1 {
			time.Sleep(5 * time.Second)
			continue
		}
		b.log(cCyan("Status  :") + " " + cRed("Failed to Fetch Profile Data") + " " + cMagenta("-") + " " + cYellow(err.Error()))
	}
	return nil
}

func (b *Bot) pointsBalance(token string, proxyURL string, retries int) map[string]interface{} {
	url := b.BaseAPI + "/api/v1/points/balance"
	for attempt := 0; attempt < retries; attempt++ {
		headers := b.initializeHeaders(token)
		resp, err := b.requestJSON("GET", url, headers, proxyURL, 60*time.Second)
		if err == nil {
			return resp
		}
		if attempt < retries-1 {
			time.Sleep(5 * time.Second)
			continue
		}
		b.log(cCyan("Balance :") + " " + cRed("Failed to Fetch Earned Vpoints") + " " + cMagenta("-") + " " + cYellow(err.Error()))
	}
	return nil
}

func (b *Bot) checkinStatus(token string, proxyURL string, retries int) map[string]interface{} {
	url := b.BaseAPI + "/api/v1/task/checkin/status"
	for attempt := 0; attempt < retries; attempt++ {
		headers := b.initializeHeaders(token)
		resp, err := b.requestJSON("GET", url, headers, proxyURL, 60*time.Second)
		if err == nil {
			return resp
		}
		if attempt < retries-1 {
			time.Sleep(5 * time.Second)
			continue
		}
		b.log(cCyan("Check-In:") + " " + cRed("Failed to Fetch Status") + " " + cMagenta("-") + " " + cYellow(err.Error()))
	}
	return nil
}

func (b *Bot) performCheckin(token string, proxyURL string, retries int) map[string]interface{} {
	url := b.BaseAPI + "/api/v1/task/checkin"
	for attempt := 0; attempt < retries; attempt++ {
		headers := b.initializeHeaders(token)
		resp, err := b.requestJSON("POST", url, headers, proxyURL, 60*time.Second)
		if err == nil {
			return resp
		}
		if attempt < retries-1 {
			time.Sleep(5 * time.Second)
			continue
		}
		b.log(cCyan("Check-In:") + " " + cRed("Failed to Perform") + " " + cMagenta("-") + " " + cYellow(err.Error()))
	}
	return nil
}

func (b *Bot) processCheckConnection(token string, proxyURL string) bool {
	for {
		if b.UseProxy {
			proxyURL = b.getNextProxyForAccount(token)
		}

		b.log(cCyan("Proxy   :") + " " + cWhite(displayProxy(proxyURL)))

		if b.checkConnection(proxyURL) {
			return true
		}

		if b.RotateProxy {
			_ = b.rotateProxyForAccount(token)
			time.Sleep(1 * time.Second)
			continue
		}
		return false
	}
}

func (b *Bot) processAccounts(token string, proxyURL string) bool {
	if !b.processCheckConnection(token, proxyURL) {
		return false
	}
	if b.UseProxy {
		proxyURL = b.getNextProxyForAccount(token)
	}

	profile := b.userProfile(token, proxyURL, 5)
	if profile == nil {
		return false
	}
	if code, ok := toInt(profile["code"]); !ok || code != 0 {
		errMsg, _ := toString(profile["message"])
		b.log(cCyan("Status  :") + " " + cRed("Failed to Fetch Profile Data") + " " + cMagenta("-") + " " + cYellow(errMsg))
		return false
	}
	data, _ := profile["data"].(map[string]interface{})
	status, _ := toString(data["status"])
	if status != "active" {
		b.log(cCyan("Status  :") + " " + cRed("Inactive User") + " " + cMagenta("-") + " " + cYellow("Complete Onboarding First"))
		return false
	}

	balance := b.pointsBalance(token, proxyURL, 5)
	if balance != nil {
		if code, ok := toInt(balance["code"]); ok && code == 0 {
			data, _ := balance["data"].(map[string]interface{})
			total := formatNumber(data["total_earned"])
			b.log(cCyan("Balance :") + " " + cWhite(total) + cWhite(" Vpoints"))
		} else {
			errMsg, _ := toString(balance["message"])
			b.log(cCyan("Balance :") + " " + cRed("Failed to Fetch Earned Vpoints") + " " + cMagenta("-") + " " + cYellow(errMsg))
		}
	}

	checkin := b.checkinStatus(token, proxyURL, 5)
	if checkin != nil {
		if code, ok := toInt(checkin["code"]); ok && code == 0 {
			data, _ := checkin["data"].(map[string]interface{})
			checked, _ := toBool(data["checked_in"])
			if checked {
				b.log(cCyan("Check-In:") + " " + cYellow("Already Performed"))
			} else {
				perform := b.performCheckin(token, proxyURL, 5)
				if perform != nil {
					if code, ok := toInt(perform["code"]); ok && code == 0 {
						data, _ := perform["data"].(map[string]interface{})
						reward := formatNumber(data["reward"])
						b.log(cCyan("Check-In:") + " " + cGreen("Success") + " " + cMagenta("-") + " " + cCyan("Reward: ") + cWhite(reward) + cWhite(" Vpoints"))
					} else {
						errMsg, _ := toString(perform["message"])
						b.log(cCyan("Check-In:") + " " + cRed("Failed to Perform") + " " + cMagenta("-") + " " + cYellow(errMsg))
					}
				}
			}
		} else {
			errMsg, _ := toString(checkin["message"])
			b.log(cCyan("Check-In:") + " " + cRed("Failed to Fetch Status") + " " + cMagenta("-") + " " + cYellow(errMsg))
		}
	}
	return true
}

func (b *Bot) run() error {
	tokens := b.loadTokens()
	if len(tokens) == 0 {
		fmt.Println("No Tokens Loaded.")
		return nil
	}

	b.printQuestion()

	for {
		b.clearTerminal()
		b.welcome()
		b.log(cGreen("Account's Total: ") + cWhite(fmt.Sprintf("%d", len(tokens))))

		if b.UseProxy {
			b.loadProxies()
		}

		separator := strings.Repeat("=", 25)
		for i, token := range tokens {
			sepLine := fmt.Sprintf("%s[ %d - %d ]%s", separator, i+1, len(tokens), separator)
			b.log(gradient(sepLine, []string{clrPurpleDeep, clrPurpleBright, clrMagentaNeon, clrCyanNeon}))
			exp, err := b.decodeJWTExp(token)
			if err != nil {
				b.log(cCyan("Status  :") + " " + cRed("Invalid Jwt Token") + " " + cMagenta("-") + " " + cYellow(err.Error()))
				continue
			}
			if time.Now().Unix() > exp {
				b.log(cCyan("Status  :") + " " + cRed("Jwt Token Already Expired"))
				continue
			}
			_ = b.processAccounts(token, "")
			time.Sleep(time.Duration(2*b.Rand.Intn(2)+2) * time.Second)
		}

		b.log(gradient(strings.Repeat("=", 60), []string{clrPurpleDeep, clrPurpleBright, clrMagentaNeon, clrCyanNeon}))
		delay := 24 * 60 * 60
		for delay > 0 {
			formatted := b.formatSeconds(delay)
			line := fmt.Sprintf("[ Wait for %s ... ] | All Accounts Have Been Processed...", formatted)
			if noColor {
				fmt.Printf("%s\r", line)
			} else {
				fmt.Printf("%s[ Wait for %s%s%s ... ]%s %s|%s %sAll Accounts Have Been Processed...%s\r",
					clrPurpleBright, clrCyanNeon, formatted, clrPurpleBright, clrReset, clrWhite, clrReset, clrMagentaNeon, clrReset)
			}
			time.Sleep(1 * time.Second)
			delay--
		}
	}
}

func toString(v interface{}) (string, bool) {
	if v == nil {
		return "", false
	}
	switch t := v.(type) {
	case string:
		return t, true
	case json.Number:
		return t.String(), true
	case float64:
		if t == math.Trunc(t) {
			return fmt.Sprintf("%.0f", t), true
		}
		return fmt.Sprintf("%v", t), true
	default:
		return fmt.Sprintf("%v", t), true
	}
}

func toInt(v interface{}) (int, bool) {
	if v == nil {
		return 0, false
	}
	switch t := v.(type) {
	case int:
		return t, true
	case int64:
		return int(t), true
	case float64:
		return int(t), true
	case json.Number:
		i, err := t.Int64()
		if err != nil {
			return 0, false
		}
		return int(i), true
	default:
		return 0, false
	}
}

func toInt64(v interface{}) (int64, bool) {
	if v == nil {
		return 0, false
	}
	switch t := v.(type) {
	case int:
		return int64(t), true
	case int64:
		return t, true
	case float64:
		return int64(t), true
	case json.Number:
		i, err := t.Int64()
		if err != nil {
			return 0, false
		}
		return i, true
	default:
		return 0, false
	}
}

func toBool(v interface{}) (bool, bool) {
	if v == nil {
		return false, false
	}
	switch t := v.(type) {
	case bool:
		return t, true
	default:
		return false, false
	}
}

func formatNumber(v interface{}) string {
	if v == nil {
		return "0"
	}
	switch t := v.(type) {
	case json.Number:
		return t.String()
	case float64:
		if t == math.Trunc(t) {
			return fmt.Sprintf("%.0f", t)
		}
		return fmt.Sprintf("%v", t)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case string:
		return t
	default:
		return fmt.Sprintf("%v", t)
	}
}

func readNonEmptyLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	var out []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out, nil
}

func main() {
	bot := NewBot()
	if err := bot.run(); err != nil {
		bot.log(cRed(fmt.Sprintf("Error: %v", err)))
	}
}
