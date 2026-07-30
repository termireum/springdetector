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

func isSpringBoot(body string, headers http.Header) bool {
	indicators := []string{
		`"status":"UP"`,
		`"status": "UP"`,
		`"status":"DOWN"`,
		`"diskSpace"`,
		`"components"`,
		`"_links"`,
		`"actuator"`,
		`"configprops"`,
		`"spring"`,
		`"Spring Boot"`,
		`Whitelabel Error Page`,
		`There was an unexpected error`,
		`application/vnd.spring-boot.actuator`,
	}
	for _, ind := range indicators {
		if strings.Contains(body, ind) {
			return true
		}
	}
	ct := headers.Get("Content-Type")
	if strings.Contains(ct, "application/vnd.spring-boot.actuator") {
		return true
	}
	return false
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

func probeEndpoint(client *http.Client, baseURL, endpoint string, extraHeaders map[string]string) *Finding {
	url := baseURL + endpoint

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SpringDetector/1.0)")
	req.Header.Set("Accept", "*/*")
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

	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	bodySnippet := string(buf[:n])
	size := len(bodySnippet)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if isSpringBoot(bodySnippet, resp.Header) || isInterestingEndpoint(endpoint) {
			return &Finding{
				Endpoint:   endpoint,
				StatusCode: resp.StatusCode,
				Size:       size,
			}
		}
	}

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		if isInterestingEndpoint(endpoint) {
			return &Finding{
				Endpoint:   endpoint,
				StatusCode: resp.StatusCode,
				Size:       size,
			}
		}
	}

	return nil
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
					result := probeEndpoint(client, baseURL, ep, cfg.Headers)
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

	// Parse schemes
	for _, s := range strings.Split(schemeStr, ",") {
		cfg.Schemes = append(cfg.Schemes, strings.TrimSpace(s))
	}

	// Parse extra headers
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
				colorCyan, f.Subdomain, colorReset)
			fmt.Printf("        %sEndpoint:%s %s\n", colorBold, colorReset, f.Endpoint)
			fmt.Printf("        %sStatus:%s  %s%d%s | Size: %d bytes\n",
				colorBold, colorReset, sc, f.StatusCode, colorReset, f.Size)
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
	if len(cfg.FilterCodes) > 0 {
		fmt.Printf(" Filter       : %s%v%s\n", colorCyan, cfg.FilterCodes, colorReset)
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
				fmt.Printf("    %s%-3d%s  %s\n", sc, f.StatusCode, colorReset, f.Endpoint)
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
			f.WriteString(fmt.Sprintf("  [%d] %s (size: %d)\n", fi.StatusCode, fi.Endpoint, fi.Size))
		}
		f.WriteString("\n")
	}
}
