package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ANSI colors
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
)

type Finding struct {
	Subdomain  string
	Endpoint   string
	StatusCode int
	Size       int
	Score      int
	Reasons    []string
}

type Config struct {
	Target        string
	WordlistPath  string
	Threads       int
	Timeout       int
	OutputFile    string
	SkipSubfinder bool
	Schemes       []string
	Headers       map[string]string
	Verbose       bool
	FilterCodes   []int
	MinScore      int
}

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
	fmt.Println(colorGray + "    Spring Boot Endpoint Detector | by termireum" + colorReset)
	fmt.Println()
}

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
		if strings.HasPrefix(line, "TRACE ") || strings.HasPrefix(line, "OPTIONS ") ||
			strings.HasPrefix(line, "PUT ") || strings.HasPrefix(line, "DELETE ") ||
			strings.HasPrefix(line, "PATCH ") || strings.HasPrefix(line, "HEAD ") ||
			strings.HasPrefix(line, "CONNECT ") {
			continue
		}
		if strings.HasPrefix(line, "?") || strings.HasPrefix(line, "&") {
			continue
		}
		if strings.HasPrefix(line, "# ") {
			continue
		}
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

func runSubfinder(domain string) ([]string, error) {
	fmt.Printf("%s[*]%s Running subfinder on %s...\n", colorCyan, colorReset, domain)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "subfinder", "-d", domain, "-silent")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("subfinder error: %v", err)
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

type ScoreResult struct {
	Score   int
	Reasons []string
}

func scoreResponse(body string, headers http.Header, endpoint string, statusCode int) ScoreResult {
	var result ScoreResult

	// Skor 5 — paling kuat, header resmi Spring Boot
	officialHeaders := map[string]string{
		"application/vnd.spring-boot.actuator.v1+json": "official Spring Boot actuator v1 Content-Type",
		"application/vnd.spring-boot.actuator.v2+json": "official Spring Boot actuator v2 Content-Type",
		"application/vnd.spring-boot.actuator.v3+json": "official Spring Boot actuator v3 Content-Type",
	}
	ct := headers.Get("Content-Type")
	for pattern, reason := range officialHeaders {
		if strings.Contains(ct, pattern) {
			result.Score += 5
			result.Reasons = append(result.Reasons, reason)
		}
	}

	// Skor 3 — indikator kuat dari body
	strongIndicators := map[string]string{
		`"_links"`:            "actuator _links structure",
		`"propertySources"`:   "propertySources (/env signature)",
		`"classLoader"`:       "classLoader (/beans signature)",
		`"threadName"`:        "threadName (/threaddump signature)",
		`"configuredLevel"`:   "configuredLevel (/loggers signature)",
		`"measurements"`:      "measurements (/metrics signature)",
		`"diskSpace"`:         "diskSpace component (/health)",
		`"configprops"`:       "configprops field detected",
		`"requestMappings"`:   "requestMappings (/mappings signature)",
		`"reportedApplications"`: "reportedApplications (/httptrace)",
		`"traces"`:            "traces field (/httptrace signature)",
		`"value"`:             "Jolokia value response",
		`Whitelabel Error Page`: "Spring Whitelabel error page",
		`"timestamp"`:         "Spring error timestamp field",
		`"path"`:              "Spring error path field",
		`"error"`:             "Spring error field",
	}
	// Kombinasi timestamp+path+error = Spring error response (skor akumulatif)
	springErrorFields := 0
	for pattern, reason := range strongIndicators {
		if strings.Contains(body, pattern) {
			// Khusus error fields, akumulasi dulu
			if pattern == `"timestamp"` || pattern == `"path"` || pattern == `"error"` {
				springErrorFields++
				// Baru tambah skor kalau minimal 2 dari 3 field ada
				if springErrorFields == 2 {
					result.Score += 3
					result.Reasons = append(result.Reasons, "Spring error response (timestamp+path+error)")
				}
				continue
			}
			result.Score += 3
			result.Reasons = append(result.Reasons, reason)
		}
	}

	// Skor 2 — indikator medium
	mediumIndicators := map[string]string{
		`"status":"UP"`:    "health status UP",
		`"status": "UP"`:  "health status UP",
		`"status":"DOWN"`: "health status DOWN",
		`"status":"OUT_OF_SERVICE"`: "health OUT_OF_SERVICE",
		`"components"`:    "health components structure",
		`"details"`:       "health details field",
		`"started"`:       "Spring started event",
		`"uptime"`:        "application uptime",
		`"build"`:         "build info field",
		`"git"`:           "git info field",
	}
	for pattern, reason := range mediumIndicators {
		if strings.Contains(body, pattern) {
			result.Score += 2
			result.Reasons = append(result.Reasons, reason)
		}
	}

	// Skor 1 — indikator lemah (butuh kombinasi)
	weakIndicators := map[string]string{
		`"status"`:  "generic status field",
		`"message"`: "generic message field",
		`"info"`:    "generic info field",
	}
	for pattern, reason := range weakIndicators {
		if strings.Contains(body, pattern) {
			result.Score += 1
			result.Reasons = append(result.Reasons, reason)
		}
	}

	// Bonus: JSON response pada 200
	if strings.Contains(ct, "application/json") && statusCode == 200 {
		result.Score += 1
		result.Reasons = append(result.Reasons, "JSON response on 200")
	}

	// Penalti: response terlalu pendek (kemungkinan redirect / halaman kosong)
	if len(body) < 30 && result.Score > 0 {
		result.Score -= 2
		result.Reasons = append(result.Reasons, "[penalty] response body terlalu pendek")
	}

	// Penalti: ada indikasi bukan Spring (HTML biasa, login page generik)
	falsePositiveIndicators := []string{
		"<html", "<!DOCTYPE", "<title>Login</title>",
		"nginx", "Apache", "IIS",
		"jQuery", "bootstrap.min.js",
	}
	for _, fp := range falsePositiveIndicators {
		if strings.Contains(strings.ToLower(body), strings.ToLower(fp)) {
			result.Score -= 2
			result.Reasons = append(result.Reasons, "[penalty] kemungkinan halaman non-Spring: "+fp)
			break
		}
	}

	return result
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

func probeEndpoint(client *http.Client, baseURL, endpoint string, extraHeaders map[string]string, minScore int) *Finding {
	url := baseURL + endpoint

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SpringDetector/1.0)")
	req.Header.Set("Accept", "application/json, */*")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 || resp.StatusCode == 400 {
		return nil
	}

	// Baca lebih banyak body untuk scoring yang akurat
	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	bodySnippet := string(buf[:n])
	size := len(bodySnippet)

	// Scoring
	scored := scoreResponse(bodySnippet, resp.Header, endpoint, resp.StatusCode)

	// Untuk 401/403 pada endpoint Spring yang dikenal, beri bonus skor
	if (resp.StatusCode == 401 || resp.StatusCode == 403) && isInterestingEndpoint(endpoint) {
		scored.Score += 2
		scored.Reasons = append(scored.Reasons, fmt.Sprintf("auth-protected Spring endpoint (%d)", resp.StatusCode))
	}

	if scored.Score < minScore {
		return nil
	}

	return &Finding{
		Endpoint:   endpoint,
		StatusCode: resp.StatusCode,
		Size:       size,
		Score:      scored.Score,
		Reasons:    scored.Reasons,
	}
}

func isInterestingEndpoint(endpoint string) bool {
	interesting := []string{
		"actuator", "env", "beans", "heapdump", "configprops",
		"mappings", "httptrace", "jolokia", "metrics", "logfile",
		"health", "info", "prometheus", "threaddump", "sessions",
		"loggers", "flyway", "liquibase", "gateway", "swagger",
		"api-docs", "openapi", "monitoring",
	}
	ep := strings.ToLower(endpoint)
	for _, kw := range interesting {
		if strings.Contains(ep, kw) {
			return true
		}
	}
	return false
}

func scanSubdomain(cfg *Config, client *http.Client, subdomain string, endpoints []string, findings chan<- Finding, wg *sync.WaitGroup) {
	defer wg.Done()

	for _, scheme := range cfg.Schemes {
		baseURL := scheme + "://" + subdomain

		req, err := http.NewRequest("GET", baseURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SpringDetector/1.0)")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		fmt.Printf("%s[~]%s Scanning %s (%d endpoints)\n", colorYellow, colorReset, baseURL, len(endpoints))

		jobCh := make(chan string, len(endpoints))
		var innerWg sync.WaitGroup

		for i := 0; i < cfg.Threads; i++ {
			innerWg.Add(1)
			go func() {
				defer innerWg.Done()
				for ep := range jobCh {
					result := probeEndpoint(client, baseURL, ep, cfg.Headers, cfg.MinScore)
					if result != nil && shouldShow(result.StatusCode, cfg.FilterCodes) {
						result.Subdomain = baseURL
						findings <- *result
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

func scoreBar(score int) string {
	maxScore := 10
	if score > maxScore {
		score = maxScore
	}
	filled := score
	empty := maxScore - filled
	bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)
	var color string
	switch {
	case score >= 7:
		color = colorGreen
	case score >= 4:
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
	case code == 401 || code == 403:
		return colorYellow
	default:
		return colorRed
	}
}

func main() {
	banner()

	var cfg Config
	var schemeStr string
	var headerStr string
	var filterStr string

	flag.StringVar(&cfg.Target, "u", "", "Target domain (e.g. example.com)")
	flag.StringVar(&cfg.WordlistPath, "w", "", "Path to wordlist file (required)")
	flag.IntVar(&cfg.Threads, "t", 20, "Number of concurrent threads per subdomain")
	flag.IntVar(&cfg.Timeout, "timeout", 10, "HTTP timeout in seconds")
	flag.StringVar(&cfg.OutputFile, "o", "", "Output file for findings (optional)")
	flag.BoolVar(&cfg.SkipSubfinder, "no-subfinder", false, "Skip subfinder, scan target domain directly")
	flag.StringVar(&schemeStr, "schemes", "https,http", "Schemes to test (comma-separated)")
	flag.StringVar(&headerStr, "H", "", "Extra headers (format: 'Key:Value,Key2:Value2')")
	flag.BoolVar(&cfg.Verbose, "v", false, "Verbose output")
	flag.StringVar(&filterStr, "fc", "", "Filter by status code (e.g. 200 or 200,403)")
	flag.IntVar(&cfg.MinScore, "ms", 3, "Minimum confidence score to report (1-10, default: 3)")
	flag.Parse()

	if cfg.Target == "" {
		fmt.Printf("%s[!]%s No target specified. Use -u example.com\n", colorRed, colorReset)
		flag.Usage()
		os.Exit(1)
	}
	if cfg.WordlistPath == "" {
		fmt.Printf("%s[!]%s No wordlist specified. Use -w /path/to/wordlist.txt\n", colorRed, colorReset)
		flag.Usage()
		os.Exit(1)
	}

	// Parse filter codes
	if filterStr != "" {
		for _, s := range strings.Split(filterStr, ",") {
			s = strings.TrimSpace(s)
			if code, err := strconv.Atoi(s); err == nil {
				cfg.FilterCodes = append(cfg.FilterCodes, code)
			}
		}
		fmt.Printf("%s[*]%s Filter aktif: hanya menampilkan status code %s\n", colorCyan, colorReset, filterStr)
	}

	fmt.Printf("%s[*]%s Minimum confidence score: %d/10\n", colorCyan, colorReset, cfg.MinScore)

	// Parse schemes
	for _, s := range strings.Split(schemeStr, ",") {
		cfg.Schemes = append(cfg.Schemes, strings.TrimSpace(s))
	}

	// Default bypass headers
	cfg.Headers = map[string]string{
		"X-Forwarded-For":  "127.0.0.1",
		"X-Forwarded-Host": "localhost",
	}
	if headerStr != "" {
		for _, pair := range strings.Split(headerStr, ",") {
			parts := strings.SplitN(pair, ":", 2)
			if len(parts) == 2 {
				cfg.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	// Load wordlist
	fmt.Printf("%s[*]%s Loading wordlist: %s\n", colorCyan, colorReset, cfg.WordlistPath)
	endpoints, err := loadWordlist(cfg.WordlistPath)
	if err != nil {
		fmt.Printf("%s[!]%s Failed to load wordlist: %v\n", colorRed, colorReset, err)
		os.Exit(1)
	}
	fmt.Printf("%s[+]%s Loaded %d unique endpoints\n", colorGreen, colorReset, len(endpoints))

	// Get subdomains
	var subdomains []string
	if cfg.SkipSubfinder {
		subdomains = []string{cfg.Target}
	} else {
		subs, err := runSubfinder(cfg.Target)
		if err != nil {
			fmt.Printf("%s[!]%s Subfinder failed: %v\n%s[*]%s Falling back to scanning target directly\n",
				colorYellow, colorReset, err, colorCyan, colorReset)
			subdomains = []string{cfg.Target}
		} else {
			subdomains = subs
			subdomains = append(subdomains, cfg.Target)
		}
	}

	fmt.Printf("%s[+]%s Found %d subdomains to scan\n", colorGreen, colorReset, len(subdomains))
	fmt.Println()

	// HTTP client
	client := &http.Client{
		Timeout: time.Duration(cfg.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	findings := make(chan Finding, 1000)
	var allFindings []Finding
	var resultsMu sync.Mutex

	done := make(chan struct{})
	go func() {
		defer close(done)
		for f := range findings {
			resultsMu.Lock()
			allFindings = append(allFindings, f)
			resultsMu.Unlock()

			sc := statusColor(f.StatusCode)
			fmt.Printf("\n%s[FOUND]%s %s%s%s\n",
				colorGreen+colorBold, colorReset,
				colorCyan+colorBold, f.Subdomain, colorReset)
			fmt.Printf("        %sEndpoint :%s %s\n", colorBold, colorReset, f.Endpoint)
			fmt.Printf("        %sStatus   :%s %s%d%s | Size: %d bytes\n",
				colorBold, colorReset, sc, f.StatusCode, colorReset, f.Size)
			fmt.Printf("        %sScore    :%s %s\n", colorBold, colorReset, scoreBar(f.Score))
			// Tampilkan reasons, filter penalty agar tidak berisik
			var cleanReasons []string
			for _, r := range f.Reasons {
				if !strings.HasPrefix(r, "[penalty]") {
					cleanReasons = append(cleanReasons, r)
				}
			}
			fmt.Printf("        %sEvidence :%s %s\n", colorBold, colorReset, strings.Join(cleanReasons, ", "))
		}
	}()

	semaphore := make(chan struct{}, 5)
	var wg sync.WaitGroup

	for _, sub := range subdomains {
		semaphore <- struct{}{}
		wg.Add(1)
		go func(s string) {
			defer func() { <-semaphore }()
			scanSubdomain(&cfg, client, s, endpoints, findings, &wg)
		}(sub)
	}

	wg.Wait()
	close(findings)
	<-done

	// Summary
	fmt.Println()
	fmt.Println(colorBold + "═══════════════════════════════════════════════════════" + colorReset)
	fmt.Printf("%s SCAN COMPLETE%s\n", colorBold+colorCyan, colorReset)
	fmt.Println(colorBold + "═══════════════════════════════════════════════════════" + colorReset)
	fmt.Printf(" Target       : %s\n", cfg.Target)
	fmt.Printf(" Subdomains   : %d\n", len(subdomains))
	fmt.Printf(" Endpoints    : %d\n", len(endpoints))
	fmt.Printf(" Min Score    : %d/10\n", cfg.MinScore)
	if len(cfg.FilterCodes) > 0 {
		fmt.Printf(" Filter       : %v\n", cfg.FilterCodes)
	}
	fmt.Printf(" Findings     : %s%d%s\n", colorGreen+colorBold, len(allFindings), colorReset)
	fmt.Println()

	if len(allFindings) == 0 {
		fmt.Printf("%s[-]%s No Spring Boot endpoints found.\n", colorGray, colorReset)
	} else {
		fmt.Printf("%s[+]%s Exposed Spring Boot Endpoints:\n\n", colorGreen+colorBold, colorReset)

		grouped := map[string][]Finding{}
		for _, f := range allFindings {
			grouped[f.Subdomain] = append(grouped[f.Subdomain], f)
		}

		for host, flist := range grouped {
			fmt.Printf("  %s%s%s\n", colorCyan+colorBold, host, colorReset)
			for _, f := range flist {
				sc := statusColor(f.StatusCode)
				fmt.Printf("    %s%-3d%s  %-50s  score:%d/10\n",
					sc, f.StatusCode, colorReset, f.Endpoint, f.Score)
			}
			fmt.Println()
		}
	}

	if cfg.OutputFile != "" && len(allFindings) > 0 {
		saveFindings(cfg.OutputFile, allFindings)
		fmt.Printf("%s[+]%s Results saved to: %s\n", colorGreen, colorReset, cfg.OutputFile)
	}
}

func saveFindings(path string, findings []Finding) {
	f, err := os.Create(path)
	if err != nil {
		fmt.Printf("\033[31m[!]\033[0m Failed to create output file: %v\n", err)
		return
	}
	defer f.Close()

	f.WriteString("# SpringDetector Results\n")
	f.WriteString(fmt.Sprintf("# Generated: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))

	grouped := map[string][]Finding{}
	for _, fi := range findings {
		grouped[fi.Subdomain] = append(grouped[fi.Subdomain], fi)
	}

	for host, flist := range grouped {
		f.WriteString(fmt.Sprintf("[%s]\n", host))
		for _, fi := range flist {
			var cleanReasons []string
			for _, r := range fi.Reasons {
				if !strings.HasPrefix(r, "[penalty]") {
					cleanReasons = append(cleanReasons, r)
				}
			}
			f.WriteString(fmt.Sprintf("  [%d] %s (score:%d/10, size:%d)\n",
				fi.StatusCode, fi.Endpoint, fi.Score, fi.Size))
			f.WriteString(fmt.Sprintf("       evidence: %s\n", strings.Join(cleanReasons, ", ")))
		}
		f.WriteString("\n")
	}
}
