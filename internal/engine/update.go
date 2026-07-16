package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type Release struct {
	TagName string `json:"tag_name"`
	Name    string `json:"name"`
	Body    string `json:"body"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int64  `json:"size"`
	} `json:"assets"`
}

func CheckUpdate(owner, repo, currentVersion string) (available bool, latestVersion, changelog, downloadURL string, sha256sum string) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, repo)
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		return false, "", "", "", ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false, "", "", "", ""
	}

	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return false, "", "", "", ""
	}

	latestVersion = release.TagName
	if latestVersion != "" && latestVersion[0] == 'v' {
		latestVersion = latestVersion[1:]
	}

	if currentVersion == "" || latestVersion == currentVersion {
		return false, "", "", "", ""
	}

	if compareVersions(latestVersion, currentVersion) <= 0 {
		return false, "", "", "", ""
	}

	changelog = release.Body
	if len(changelog) > 500 {
		changelog = changelog[:497] + "..."
	}

	for _, asset := range release.Assets {
		assetName := strings.ToLower(asset.Name)
		if strings.Contains(assetName, "sha256") || strings.Contains(assetName, "checksum") {
			sha256sum = fetchSHA256(asset.BrowserDownloadURL)
			continue
		}

		if strings.Contains(assetName, runtime.GOOS) && strings.Contains(assetName, runtime.GOARCH) {
			downloadURL = asset.BrowserDownloadURL
			continue
		}

		if strings.HasSuffix(assetName, ".exe") && runtime.GOOS == "windows" {
			downloadURL = asset.BrowserDownloadURL
		}
	}

	if downloadURL == "" && len(release.Assets) > 0 {
		downloadURL = release.Assets[0].BrowserDownloadURL
	}

	return true, latestVersion, changelog, downloadURL, sha256sum
}

func fetchSHA256(url string) string {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	data := make([]byte, 10000)
	n, _ := resp.Body.Read(data)
	content := string(data[:n])

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) < 64 {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 1 && len(parts[0]) == 64 {
			return parts[0]
		}
	}
	return ""
}

func compareVersions(a, b string) int {
	var aMajor, aMinor, aPatch int
	var bMajor, bMinor, bPatch int
	fmt.Sscanf(a, "%d.%d.%d", &aMajor, &aMinor, &aPatch)
	fmt.Sscanf(b, "%d.%d.%d", &bMajor, &bMinor, &bPatch)

	if aMajor != bMajor {
		return aMajor - bMajor
	}
	if aMinor != bMinor {
		return aMinor - bMinor
	}
	return aPatch - bPatch
}

func SelfUpdate(downloadURL, expectedSHA256 string) (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "Could not find executable path", err
	}

	resp, err := http.Get(downloadURL)
	if err != nil {
		return "Download failed", fmt.Errorf("download error: %w", err)
	}
	defer resp.Body.Close()

	tmpFile, err := os.CreateTemp("", "sc-checker-update-*.exe")
	if err != nil {
		return "Temp file error", err
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	hasher := sha256.New()
	writer := io.MultiWriter(tmpFile, hasher)

	_, err = io.Copy(writer, resp.Body)
	tmpFile.Close()

	if err != nil {
		return "Download incomplete", fmt.Errorf("download write error: %w", err)
	}

	actualSHA256 := hex.EncodeToString(hasher.Sum(nil))

	if expectedSHA256 != "" {
		if !strings.EqualFold(actualSHA256, expectedSHA256) {
			return fmt.Sprintf("SHA256 mismatch\nExpected: %s\nGot:      %s", expectedSHA256[:16]+"...", actualSHA256[:16]+"..."),
				fmt.Errorf("checksum verification failed")
		}
	}

	batchPath := filepath.Join(os.TempDir(), "sc-checker-update.bat")
	batch := fmt.Sprintf(`@echo off
timeout /t 2 /nobreak >nul
if exist "%s.old" del /f "%s.old"
ren "%s" "%s.old"
move /y "%s" "%s"
if exist "%s" (
    start "" "%s"
    del /f "%%~f0"
) else (
    echo Update failed, restoring backup
    ren "%s.old" "%s"
    start "" "%s"
)
exit`, exePath, exePath, exePath, filepath.Base(exePath), tmpPath, exePath, exePath, exePath, exePath, exePath, exePath)

	os.WriteFile(batchPath, []byte(batch), 0644)

	cmd := exec.Command("cmd", "/C", batchPath)
	cmd.Start()

	return "Update started", nil
}
