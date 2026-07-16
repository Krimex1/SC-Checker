package engine

import (
	"fmt"
	"net/url"
	"sc-checker-go/internal/config"
	"sc-checker-go/internal/model"
	"sort"
	"strings"
	"sync"
)

func ScanPaths(base string, paths []string, client *ConcurrentClient, stopCh <-chan struct{}) ([]model.PathItem, []string) {
	uniquePaths := make(map[string]bool)
	for _, p := range paths {
		uniquePaths[p] = true
	}

	var pathList []string
	for p := range uniquePaths {
		pathList = append(pathList, p)
	}
	sort.Strings(pathList)

	var found []model.PathItem
	var mu sync.Mutex
	sem := make(chan struct{}, config.PathWorkers)
	var wg sync.WaitGroup

	for i, path := range pathList {
		select {
		case <-stopCh:
			return found, nil
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, p string) {
			defer wg.Done()
			defer func() { <-sem }()

			fullURL, err := url.JoinPath(base, p)
			if err != nil {
				return
			}

			resp, _, err := client.Get(idx, fullURL, nil)
			if err != nil || resp == nil {
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == 200 {
				bodyBuf := make([]byte, config.BodyPreviewLong)
				n, _ := resp.Body.Read(bodyBuf)
				body := string(bodyBuf[:n])
				size := int(resp.ContentLength)
				if size <= 0 {
					size = n
				}

				item := model.PathItem{Path: fmt.Sprintf("/%s", p), Status: resp.StatusCode, Size: size}
				mu.Lock()
				found = append(found, item)
				mu.Unlock()

				if _, ok := CriticalPaths[strings.TrimPrefix(p, "/")]; ok {
					if isRealCritical(strings.TrimPrefix(p, "/"), body, size) {
						mu.Lock()
						found = append(found, item)
						mu.Unlock()
					}
				}
			}
		}(i, path)
	}
	wg.Wait()

	sort.Slice(found, func(i, j int) bool {
		if found[i].Status != found[j].Status {
			return found[i].Status < found[j].Status
		}
		return strings.Compare(found[i].Path, found[j].Path) < 0
	})

	var critical []string
	seen := make(map[string]bool)
	for _, item := range found {
		p := strings.TrimPrefix(item.Path, "/")
		if _, ok := CriticalPaths[p]; ok && item.Status == 200 {
			if !seen[p] {
				seen[p] = true
				critical = append(critical, p)
			}
		}
	}

	return found, critical
}

func isSoft404(body string) bool {
	lower := body
	if len(lower) > 3000 {
		lower = lower[:3000]
	}
	lower = strings.ToLower(lower)
	for _, sig := range config.Soft404Signatures {
		if strings.Contains(lower, sig) {
			return true
		}
	}
	return false
}

func isRealCritical(path, body string, size int) bool {
	if isSoft404(body) {
		return false
	}
	if size < 10 {
		return false
	}

	rules, ok := CriticalContentRules[path]
	if !ok {
		lower := body
		if len(lower) > 2000 {
			lower = lower[:2000]
		}
		lower = strings.ToLower(lower)
		for _, kw := range []string{"sign in", "log in", "please login", "access denied", "forbidden", "just a moment", "checking your browser"} {
			if strings.Contains(lower, kw) {
				return false
			}
		}
		if strings.Contains(lower, "<form") && (strings.Contains(lower, "password") || strings.Contains(lower, "login")) {
			return false
		}
		return true
	}

	checkBody := body
	if len(checkBody) > 5000 {
		checkBody = body[:5000]
	}
	for _, rule := range rules {
		if strings.Contains(checkBody, rule) {
			return true
		}
	}
	return false
}
