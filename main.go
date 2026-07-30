package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ─── ANSI Colors ────────────────────────────────────────────────────────────

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
	colorWhite  = "\033[97m"
)

// ─── Structs ─────────────────────────────────────────────────────────────────

type Finding struct {
	Subdomain  string
	Endpoint   string
	StatusCode int
	Size       int
	Score      int
	Reasons    []string
	RespTime   time.Duration
	Timestamp  time.Time
}

type Config struct {
	Target        string
	WordlistPath  string
	Threads       int
	Timeout       int
	OutputFile    string
	SkipSubfinder bool
	Schemes       []string
	ExtraHeaders  map[string]string
	Verbose       bool
	FilterCodes   []int
	MinScore      int
	RateLimit     int // requests per second per host
	NoColor       bool
	FollowRedirect int
}

type HostRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*tokenBucket
	rps      int
}

// simple token bucket — no external deps
type tokenBucket struct {
	tokens   float64
	maxToken float64
	rate     float64 // tokens per nanosecond
	lastTime time.Time
	mu       sync.Mutex
}

func newTokenBucket(rps int) *tokenBucket {
	return &tokenBucket{
		tokens:   float64(rps),
		maxToken: float64(rps),
		rate:     float64(rps) / float64(time.Second),
		lastTime: time.Now(),
	}
}

func (tb *tokenBucket) Wait() {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(tb.lastTime)
	tb.tokens += float64(elapsed) * tb.rate
	if tb.tokens > tb.maxToken {
		tb.tokens = tb.maxToken
	}
	tb.lastTime = now
	if tb.tokens < 1 {
		wait := time.Duration((1 - tb.tokens) / tb.rate)
		tb.mu.Unlock()
		time.Sleep(wait)
		tb.mu.Lock()
		tb.tokens = 0
	} else {
		tb.tokens--
	}
}

func newHostRateLimiter(rps int) *HostRateLimiter {
	return &HostRateLimiter{
		limiters: make(map[string]*tokenBucket),
		rps:      rps,
	}
}

func (h *HostRateLimiter) Wait(host string) {
	h.mu.Lock()
	if _, ok := h.limiters[host]; !ok {
		h.limiters[host] = newTokenBucket(h.rps)
	}
	tb := h.limiters[host]
	h.mu.Unlock()
	tb.Wait()
}

// ─── Banner ──────────────────────────────────────────────────────────────────

func banner() {
	fmt.Println(colorCyan + colorBold + `
 ███████╗██████╗ ██████╗ ██╗███╗   ██╗ ██████╗ 
 ██╔════╝██╔══██╗██╔══██╗██║████╗  ██║██╔════╝ 
 ███████╗██████╔╝██████╔╝██║██╔██╗ ██║██║  ███╗
 ╚════██║██╔═══╝ ██╔══██╗██║██║╚██╗██║██║   ██║
 ███████║██║     ██║  ██║██║██║ ╚████║╚██████╔╝
 ╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 
      ██████╗ ███████╗████████╗███████╗ ██████╗████████╗ ██████╗ ██████╗ 
      ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
      ██║  ██║█████╗     ██║   █████╗  ██║        ██║   ██║   ██║██████╔╝
      ██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
      ██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
      ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝` + colorReset)
	fmt.Println(colorGray + "    Spring Boot Endpoint Detector v2.0 | by termireum" + colorReset)
	fmt.Println()
}

// ─── Wordlist ────────────────────────────────────────────────────────────────

func loadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var endpoints []string
	seen := map[string]bool{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Skip HTTP method lines
		for _, method := range []string{"TRACE ", "OPTIONS ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "CONNECT "} {
			if strings.HasPrefix(line, method) {
				line = ""
				break
			}
		}
		if line == "" {
			continue
		}
		// Skip query-param-only lines
		if strings.HasPrefix(line, "?") || strings.HasPrefix(line, "&") {
			continue
		}
		// Normalize: ensure leading slash
		if !strings.HasPrefix(line, "/") && !strings.HasPrefix(line, ";") {
			line = "/" + line
		}
		if !seen[line] {
			seen[line] = true
			endpoints = append(endpoints, line)
		}
	}
	return endpoints, scanner.Err()
}

// ─── Subfinder ───────────────────────────────────────────────────────────────

func runSubfinder(domain string) ([]string, error) {
	fmt.Printf("%s[*]%s Running subfinder on %s...\n", colorCyan, colorReset, domain)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "subfinder", "-d", domain, "-silent")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("subfinder: %v", err)
	}

	var subdomains []string
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		sub := strings.TrimSpace(scanner.Text())
		if sub != "" {
			subdomains = append(subdomains, sub)
		}
	}
	return subdomains, nil
}

// ─── Scoring ─────────────────────────────────────────────────────────────────

type scoreEntry struct {
	pattern string
	score   int
	reason  string
}

var (
	// Skor 5 — header resmi Spring Boot, paling definitif
	springHeaders = []string{
		"application/vnd.spring-boot.actuator.v1+json",
		"application/vnd.spring-boot.actuator.v2+json",
		"application/vnd.spring-boot.actuator.v3+json",
	}

	// Skor 4 — signature sangat spesifik per endpoint
	criticalBodyIndicators = []scoreEntry{
		{`"propertySources"`, 4, "propertySources (/env)"},
		{`"classLoader"`, 4, "classLoader (/beans)"},
		{`"threadName"`, 4, "threadName (/threaddump)"},
		{`"configuredLevel"`, 4, "configuredLevel (/loggers)"},
		{`"measurements"`, 4, "measurements (/metrics)"},
		{`"requestMappings"`, 4, "requestMappings (/mappings)"},
		{`"reportedApplications"`, 4, "reportedApplications (/httptrace)"},
		{`"availableExtensions"`, 4, "availableExtensions (/features)"},
		{`"registeredServices"`, 4, "registeredServices (CAS actuator)"},
		{`"flywayBeans"`, 4, "flywayBeans (/flyway)"},
		{`"liquibaseBeans"`, 4, "liquibaseBeans (/liquibase)"},
		{`"scheduledTasks"`, 4, "scheduledTasks (/scheduledtasks)"},
		{`"predicate"`, 4, "predicate (/gateway/routes)"},
		{`"value":{"type":"","value"`, 4, "Jolokia value response"},
		{`Whitelabel Error Page`, 4, "Spring Whitelabel Error Page"},
	}

	// Skor 3 — indikator kuat
	strongBodyIndicators = []scoreEntry{
		{`"_links"`, 3, "actuator _links structure"},
		{`"diskSpace"`, 3, "diskSpace (/health component)"},
		{`"configprops"`, 3, "configprops field"},
		{`"components"`, 3, "health components structure"},
		{`"traces"`, 3, "traces (/httptrace)"},
		{`"contexts"`, 3, "contexts (/beans)"},
		{`"beans"`, 3, "beans field"},
		{`"cacheManagers"`, 3, "cacheManagers (/caches)"},
		{`"jobs"`, 3, "Quartz jobs"},
	}

	// Skor 2 — indikator medium
	mediumBodyIndicators = []scoreEntry{
		{`"status":"UP"`, 2, "health status UP"},
		{`"status": "UP"`, 2, "health status UP"},
		{`"status":"DOWN"`, 2, "health status DOWN"},
		{`"status":"OUT_OF_SERVICE"`, 2, "health OUT_OF_SERVICE"},
		{`"status":"UNKNOWN"`, 2, "health status UNKNOWN"},
		{`"uptime"`, 2, "application uptime"},
		{`"startTime"`, 2, "application startTime"},
		{`"build"`, 2, "build info"},
		{`"git"`, 2, "git info"},
		{`"artifact"`, 2, "artifact info"},
		{`"version"`, 2, "version field"},
	}

	// Indikator false positive — penalti
	falsePositivePatterns = []struct {
		pattern string
		penalty int
	}{
		{"<!DOCTYPE html", -3},
		{"<html", -2},
		{"nginx", -2},
		{"Apache", -2},
		{"Microsoft-IIS", -2},
		{"jquery", -2},
		{"bootstrap.min.js", -2},
		{"login", -1},
		{"signin", -1},
		{"404 Not Found", -3},
		{"403 Forbidden", -1},
	}
)

type ScoreResult struct {
	Score   int
	Reasons []string
}

func scoreResponse(body string, headers http.Header, endpoint string, statusCode int) ScoreResult {
	var result ScoreResult
	bodyLower := strings.ToLower(body)

	// Header check — paling kuat
	ct := headers.Get("Content-Type")
	for _, h := range springHeaders {
		if strings.Contains(ct, h) {
			result.Score += 5
			result.Reasons = append(result.Reasons, "official Spring Boot actuator Content-Type")
			break
		}
	}

	// X-Application-Context header (Spring Boot 1.x)
	if headers.Get("X-Application-Context") != "" {
		result.Score += 3
		result.Reasons = append(result.Reasons, "X-Application-Context header")
	}

	// Critical body indicators
	for _, entry := range criticalBodyIndicators {
		if strings.Contains(body, entry.pattern) {
			result.Score += entry.score
			result.Reasons = append(result.Reasons, entry.reason)
		}
	}

	// Strong body indicators
	for _, entry := range strongBodyIndicators {
		if strings.Contains(body, entry.pattern) {
			result.Score += entry.score
			result.Reasons = append(result.Reasons, entry.reason)
		}
	}

	// Medium body indicators
	for _, entry := range mediumBodyIndicators {
		if strings.Contains(body, entry.pattern) {
			result.Score += entry.score
			result.Reasons = append(result.Reasons, entry.reason)
		}
	}

	// Spring error response: harus ada KOMBINASI timestamp + path + error
	hasTimestamp := strings.Contains(body, `"timestamp"`)
	hasPath := strings.Contains(body, `"path"`)
	hasError := strings.Contains(body, `"error"`)
	hasMessage := strings.Contains(body, `"message"`)
	if hasTimestamp && hasPath && hasError && hasMessage {
		result.Score += 4
		result.Reasons = append(result.Reasons, "Spring error response (timestamp+path+error+message)")
	} else if hasTimestamp && hasPath && hasError {
		result.Score += 2
		result.Reasons = append(result.Reasons, "Spring error response (timestamp+path+error)")
	}

	// JSON response on 200 — bonus kecil
	if strings.Contains(ct, "application/json") && statusCode == 200 {
		result.Score += 1
		result.Reasons = append(result.Reasons, "JSON on 200")
	}

	// Penalti false positive
	for _, fp := range falsePositivePatterns {
		if strings.Contains(bodyLower, strings.ToLower(fp.pattern)) {
			result.Score += fp.penalty
			result.Reasons = append(result.Reasons, fmt.Sprintf("[penalti] %s", fp.pattern))
		}
	}

	// Penalti body terlalu pendek (bukan heapdump)
	if len(body) < 20 && !strings.Contains(endpoint, "heapdump") {
		result.Score -= 3
		result.Reasons = append(result.Reasons, "[penalti] response terlalu pendek")
	}

	return result
}

// ─── HTTP Probe ───────────────────────────────────────────────────────────────

func probeEndpoint(client *http.Client, baseURL, endpoint string, cfg *Config) *Finding {
	url := baseURL + endpoint

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, application/vnd.spring-boot.actuator.v3+json, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	// Default bypass headers
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("X-Forwarded-Host", "localhost")
	req.Header.Set("X-Real-IP", "127.0.0.1")

	for k, v := range cfg.ExtraHeaders {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Skip jelas-jelas tidak menarik
	if resp.StatusCode == 404 || resp.StatusCode == 400 || resp.StatusCode == 405 {
		return nil
	}

	// Baca body dengan benar menggunakan io.ReadAll + LimitReader
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 16384)) // 16KB
	if err != nil {
		return nil
	}
	body := string(bodyBytes)
	size := len(bodyBytes)

	// Scoring
	scored := scoreResponse(body, resp.Header, endpoint, resp.StatusCode)

	// Bonus untuk 401/403 HANYA jika endpoint sangat spesifik Spring
	if (resp.StatusCode == 401 || resp.StatusCode == 403) && isDefinitelySpringEndpoint(endpoint) {
		scored.Score += 2
		scored.Reasons = append(scored.Reasons, fmt.Sprintf("auth-protected on known Spring endpoint (%d)", resp.StatusCode))
	}

	if scored.Score < cfg.MinScore {
		return nil
	}

	return &Finding{
		Endpoint:   endpoint,
		StatusCode: resp.StatusCode,
		Size:       size,
		Score:      scored.Score,
		Reasons:    scored.Reasons,
		RespTime:   elapsed,
		Timestamp:  time.Now(),
	}
}

// isDefinitelySpringEndpoint — lebih ketat dari isInterestingEndpoint
// hanya endpoint yang SANGAT identik dengan Spring Boot
func isDefinitelySpringEndpoint(endpoint string) bool {
	definite := []string{
		"/actuator", "actuator/", ";/actuator",
		"/heapdump", "/threaddump", "/configprops",
		"/jolokia", "/httptrace", "/flyway", "/liquibase",
		"/actuator;", "actuator;",
	}
	ep := strings.ToLower(endpoint)
	for _, kw := range definite {
		if strings.Contains(ep, kw) {
			return true
		}
	}
	return false
}

// ─── Connectivity Check ──────────────────────────────────────────────────────

// checkHost returns true and the working base URL if host is reachable
func checkHost(client *http.Client, schemes []string, host string) (bool, string) {
	for _, scheme := range schemes {
		baseURL := scheme + "://" + host
		req, err := http.NewRequest("GET", baseURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		req = req.WithContext(ctx)
		resp, err := client.Do(req)
		cancel()
		if err != nil {
			continue
		}
		resp.Body.Close()
		// Host is reachable, return the working scheme
		return true, baseURL
	}
	return false, ""
}

// ─── Scanner ─────────────────────────────────────────────────────────────────

type Stats struct {
	Probed   atomic.Int64
	Findings atomic.Int64
	Errors   atomic.Int64
}

func scanSubdomain(
	cfg *Config,
	client *http.Client,
	subdomain string,
	endpoints []string,
	findings chan<- Finding,
	wg *sync.WaitGroup,
	rateLimiter *HostRateLimiter,
	stats *Stats,
) {
	defer wg.Done()

	for _, scheme := range cfg.Schemes {
		baseURL := scheme + "://" + subdomain

		// Connectivity check
		req, err := http.NewRequest("GET", baseURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		req = req.WithContext(ctx)
		resp, err := client.Do(req)
		cancel()
		if err != nil {
			continue
		}
		resp.Body.Close()

		fmt.Printf("%s[~]%s %s — %d endpoints\n", colorYellow, colorReset, baseURL, len(endpoints))

		jobCh := make(chan string, cfg.Threads*2)
		var innerWg sync.WaitGroup

		for i := 0; i < cfg.Threads; i++ {
			innerWg.Add(1)
			go func() {
				defer innerWg.Done()
				for ep := range jobCh {
					rateLimiter.Wait(subdomain)
					stats.Probed.Add(1)
					result := probeEndpoint(client, baseURL, ep, cfg)
					if result != nil {
						if shouldShow(result.StatusCode, cfg.FilterCodes) {
							result.Subdomain = baseURL
							findings <- *result
							stats.Findings.Add(1)
						}
					}
				}
			}()
		}

		for _, ep := range endpoints {
			jobCh <- ep
		}
		close(jobCh)
		innerWg.Wait()
	}
}

func shouldShow(code int, filterCodes []int) bool {
	if len(filterCodes) == 0 {
		return true
	}
	for _, fc := range filterCodes {
		if code == fc {
			return true
		}
	}
	return false
}

// ─── Output Helpers ──────────────────────────────────────────────────────────

func scoreBar(score int) string {
	capped := score
	if capped > 10 {
		capped = 10
	}
	if capped < 0 {
		capped = 0
	}
	filled := capped
	empty := 10 - filled
	bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)
	var color string
	switch {
	case capped >= 7:
		color = colorGreen
	case capped >= 4:
		color = colorYellow
	default:
		color = colorRed
	}
	return fmt.Sprintf("%s%s%s %d/10", color, bar, colorReset, score)
}

func statusColor(code int) string {
	switch {
	case code >= 200 && code < 300:
		return colorGreen
	case code == 301 || code == 302:
		return colorCyan
	case code == 401 || code == 403:
		return colorYellow
	case code == 500:
		return colorRed
	default:
		return colorGray
	}
}

func cleanReasons(reasons []string) []string {
	var out []string
	for _, r := range reasons {
		if !strings.HasPrefix(r, "[penalti]") {
			out = append(out, r)
		}
	}
	return out
}

// ─── Save Output ─────────────────────────────────────────────────────────────

func saveFindings(path string, findings []Finding, target string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	w.WriteString("# SpringDetector v2.0 Results\n")
	w.WriteString(fmt.Sprintf("# Target    : %s\n", target))
	w.WriteString(fmt.Sprintf("# Generated : %s\n", time.Now().Format("2006-01-02 15:04:05")))
	w.WriteString(fmt.Sprintf("# Findings  : %d\n\n", len(findings)))

	// Group by subdomain
	grouped := map[string][]Finding{}
	var order []string
	for _, fi := range findings {
		if _, ok := grouped[fi.Subdomain]; !ok {
			order = append(order, fi.Subdomain)
		}
		grouped[fi.Subdomain] = append(grouped[fi.Subdomain], fi)
	}

	for _, host := range order {
		flist := grouped[host]
		// Sort by score desc
		sort.Slice(flist, func(i, j int) bool {
			return flist[i].Score > flist[j].Score
		})
		w.WriteString(fmt.Sprintf("[%s]\n", host))
		for _, fi := range flist {
			w.WriteString(fmt.Sprintf("  [%d] %s\n", fi.StatusCode, fi.Endpoint))
			w.WriteString(fmt.Sprintf("       score    : %d/10\n", fi.Score))
			w.WriteString(fmt.Sprintf("       size     : %d bytes\n", fi.Size))
			w.WriteString(fmt.Sprintf("       resptime : %s\n", fi.RespTime.Round(time.Millisecond)))
			clean := cleanReasons(fi.Reasons)
			w.WriteString(fmt.Sprintf("       evidence : %s\n", strings.Join(clean, ", ")))
			w.WriteString(fmt.Sprintf("       time     : %s\n\n", fi.Timestamp.Format("15:04:05")))
		}
	}
	return w.Flush()
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	banner()

	var cfg Config
	var schemeStr string
	var headerStr string
	var filterStr string

	flag.StringVar(&cfg.Target, "u", "", "Target domain (e.g. example.com)")
	flag.StringVar(&cfg.WordlistPath, "w", "", "Path to wordlist file (required)")
	flag.IntVar(&cfg.Threads, "t", 20, "Threads per subdomain")
	flag.IntVar(&cfg.Timeout, "timeout", 10, "HTTP timeout (seconds)")
	flag.StringVar(&cfg.OutputFile, "o", "", "Save output to file")
	flag.BoolVar(&cfg.SkipSubfinder, "no-subfinder", false, "Skip subfinder enumeration")
	flag.StringVar(&schemeStr, "schemes", "https,http", "Schemes to try (comma-separated)")
	flag.StringVar(&headerStr, "H", "", "Extra headers (Key:Value,Key2:Value2)")
	flag.BoolVar(&cfg.Verbose, "v", false, "Verbose mode")
	flag.StringVar(&filterStr, "fc", "", "Filter status codes (e.g. 200 or 200,403)")
	flag.IntVar(&cfg.MinScore, "ms", 3, "Minimum confidence score to report (1-10)")
	flag.IntVar(&cfg.RateLimit, "rl", 10, "Max requests per second per host")
	flag.Parse()

	if cfg.Target == "" || cfg.WordlistPath == "" {
		fmt.Printf("%s[!]%s Usage: springdetector -u <domain> -w <wordlist> [options]\n", colorRed, colorReset)
		flag.Usage()
		os.Exit(1)
	}

	// Parse filter codes
	if filterStr != "" {
		for _, s := range strings.Split(filterStr, ",") {
			if code, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
				cfg.FilterCodes = append(cfg.FilterCodes, code)
			}
		}
	}

	// Parse schemes
	for _, s := range strings.Split(schemeStr, ",") {
		cfg.Schemes = append(cfg.Schemes, strings.TrimSpace(s))
	}

	// Parse extra headers
	cfg.ExtraHeaders = map[string]string{}
	if headerStr != "" {
		for _, pair := range strings.Split(headerStr, ",") {
			parts := strings.SplitN(pair, ":", 2)
			if len(parts) == 2 {
				cfg.ExtraHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	// Print config
	fmt.Printf("%s[*]%s Target     : %s\n", colorCyan, colorReset, cfg.Target)
	fmt.Printf("%s[*]%s Min score  : %d/10\n", colorCyan, colorReset, cfg.MinScore)
	fmt.Printf("%s[*]%s Rate limit : %d req/s per host\n", colorCyan, colorReset, cfg.RateLimit)
	if len(cfg.FilterCodes) > 0 {
		fmt.Printf("%s[*]%s Filter     : %v\n", colorCyan, colorReset, cfg.FilterCodes)
	}

	// Load wordlist
	fmt.Printf("%s[*]%s Wordlist   : %s\n", colorCyan, colorReset, cfg.WordlistPath)
	endpoints, err := loadWordlist(cfg.WordlistPath)
	if err != nil {
		fmt.Printf("%s[!]%s Failed to load wordlist: %v\n", colorRed, colorReset, err)
		os.Exit(1)
	}
	fmt.Printf("%s[+]%s Loaded %d unique endpoints\n", colorGreen, colorReset, len(endpoints))

	// Enumerate subdomains
	var subdomains []string
	if cfg.SkipSubfinder {
		subdomains = []string{cfg.Target}
	} else {
		subs, err := runSubfinder(cfg.Target)
		if err != nil {
			fmt.Printf("%s[!]%s %v — scanning root domain only\n", colorYellow, colorReset, err)
			subdomains = []string{cfg.Target}
		} else {
			subdomains = append(subs, cfg.Target)
		}
		// Deduplicate
		seen := map[string]bool{}
		var deduped []string
		for _, s := range subdomains {
			if !seen[s] {
				seen[s] = true
				deduped = append(deduped, s)
			}
		}
		subdomains = deduped
	}
	fmt.Printf("%s[+]%s %d subdomains to scan\n\n", colorGreen, colorReset, len(subdomains))

	// HTTP client — custom transport untuk kontrol penuh
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(cfg.Timeout) * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: cfg.Threads,
		IdleConnTimeout:     60 * time.Second,
		DisableCompression:  false,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	rateLimiter := newHostRateLimiter(cfg.RateLimit)
	findings := make(chan Finding, 500)
	var allFindings []Finding
	var findingsMu sync.Mutex
	var stats Stats

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Collector goroutine
	collectorDone := make(chan struct{})
	go func() {
		defer close(collectorDone)
		for f := range findings {
			findingsMu.Lock()
			allFindings = append(allFindings, f)
			findingsMu.Unlock()

			sc := statusColor(f.StatusCode)
			clean := cleanReasons(f.Reasons)

			fmt.Printf("\n%s╔══ FOUND ══════════════════════════════════════════════╗%s\n", colorGreen+colorBold, colorReset)
			fmt.Printf("%s║%s %s%s%s\n", colorGreen+colorBold, colorReset, colorCyan+colorBold, f.Subdomain, colorReset)
			fmt.Printf("%s║%s Endpoint : %s\n", colorGreen+colorBold, colorReset, f.Endpoint)
			fmt.Printf("%s║%s Status   : %s%d%s  Size: %d bytes  Time: %s\n",
				colorGreen+colorBold, colorReset, sc, f.StatusCode, colorReset, f.Size, f.RespTime.Round(time.Millisecond))
			fmt.Printf("%s║%s Score    : %s\n", colorGreen+colorBold, colorReset, scoreBar(f.Score))
			fmt.Printf("%s║%s Evidence : %s\n", colorGreen+colorBold, colorReset, strings.Join(clean, " · "))
			fmt.Printf("%s╚═══════════════════════════════════════════════════════╝%s\n", colorGreen+colorBold, colorReset)
		}
	}()

	// Scan goroutines
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		sem := make(chan struct{}, 5) // max 5 subdomains concurrently
		var wg sync.WaitGroup
		for _, sub := range subdomains {
			select {
			case <-sigCh:
				fmt.Printf("\n%s[!]%s Interrupted — wrapping up...\n", colorYellow, colorReset)
				wg.Wait()
				return
			default:
			}
			sem <- struct{}{}
			wg.Add(1)
			go func(s string) {
				defer func() { <-sem }()
				scanSubdomain(&cfg, client, s, endpoints, findings, &wg, rateLimiter, &stats)
			}(sub)
		}
		wg.Wait()
	}()

	// Progress ticker
	ticker := time.NewTicker(10 * time.Second)
	go func() {
		for range ticker.C {
			fmt.Printf("%s[~]%s Progress: %d probed · %d found\n",
				colorGray, colorReset, stats.Probed.Load(), stats.Findings.Load())
		}
	}()

	<-scanDone
	ticker.Stop()
	close(findings)
	<-collectorDone

	// ─── Summary ───────────────────────────────────────────────────────────────

	fmt.Println()
	fmt.Println(colorBold + "═══════════════════════════════════════════════════════" + colorReset)
	fmt.Printf("%s SCAN COMPLETE%s\n", colorBold+colorCyan, colorReset)
	fmt.Println(colorBold + "═══════════════════════════════════════════════════════" + colorReset)
	fmt.Printf(" Target      : %s\n", cfg.Target)
	fmt.Printf(" Subdomains  : %d\n", len(subdomains))
	fmt.Printf(" Probed      : %d requests\n", stats.Probed.Load())
	fmt.Printf(" Min Score   : %d/10\n", cfg.MinScore)
	fmt.Printf(" Findings    : %s%d%s\n", colorGreen+colorBold, len(allFindings), colorReset)
	fmt.Println()

	if len(allFindings) == 0 {
		fmt.Printf("%s[-]%s No Spring Boot endpoints found.\n", colorGray, colorReset)
	} else {
		fmt.Printf("%s[+]%s Exposed Spring Boot Endpoints:\n\n", colorGreen+colorBold, colorReset)

		// Group & sort
		grouped := map[string][]Finding{}
		var order []string
		for _, f := range allFindings {
			if _, ok := grouped[f.Subdomain]; !ok {
				order = append(order, f.Subdomain)
			}
			grouped[f.Subdomain] = append(grouped[f.Subdomain], f)
		}

		for _, host := range order {
			flist := grouped[host]
			sort.Slice(flist, func(i, j int) bool {
				return flist[i].Score > flist[j].Score
			})
			fmt.Printf("  %s%s%s\n", colorCyan+colorBold, host, colorReset)
			for _, f := range flist {
				sc := statusColor(f.StatusCode)
				fmt.Printf("    %s%d%s  %-55s score:%d/10\n",
					sc, f.StatusCode, colorReset, f.Endpoint, f.Score)
			}
			fmt.Println()
		}
	}

	// Save
	if cfg.OutputFile != "" && len(allFindings) > 0 {
		if err := saveFindings(cfg.OutputFile, allFindings, cfg.Target); err != nil {
			fmt.Printf("%s[!]%s Failed to save: %v\n", colorRed, colorReset, err)
		} else {
			fmt.Printf("%s[+]%s Saved to: %s\n", colorGreen, colorReset, cfg.OutputFile)
		}
	}
}
