package services

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"vuln-scanner/internal/models"
)

type GitHubSearchResponse struct {
	Items []struct {
		ID              int    `json:"id"`
		Name            string `json:"name"`
		FullName        string `json:"full_name"`
		Owner           struct {
			Login string `json:"login"`
		} `json:"owner"`
		HTMLURL         string  `json:"html_url"`
		StargazersCount float64 `json:"stargazers_count"`
		Language        string  `json:"language"`
	} `json:"items"`
}

func SearchRepositories(lang string, minStars int, maxStars int, limit int) ([]models.Project, error) {
	// 1. สร้าง URL พร้อม Query String แบบช่วงดาว
	starQuery := fmt.Sprintf(">=%d", minStars)
	if maxStars > 0 {
		starQuery = fmt.Sprintf("%d..%d", minStars, maxStars)
	}

	query := fmt.Sprintf("stars:%s", starQuery)
	if lang != "" {
		query += fmt.Sprintf(" language:%s", lang)
	}

	// สร้าง URL เต็ม
	url := fmt.Sprintf("https://api.github.com/search/repositories?q=%s&sort=stars&order=desc&per_page=%d", query, limit)
	fmt.Printf("📡 GitHub Query: %s\n", query) // Debug ให้เห็นว่ายิงอะไรไป

	// 2. สร้าง Request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "Vuln-Scanner-App")
	
	token := os.Getenv("GITHUB_TOKEN")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		fmt.Println("🔑 Using GitHub Token for authentication.")
	} else {
		fmt.Println("⚠️  Warning: No GITHUB_TOKEN found. Rate limit is restricted (60/hr).")
	}

	// 3. ส่ง Request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub API Error: %s (Check rate limit or token)", resp.Status)
	}

	// 4. Decode JSON
	var result GitHubSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	// 5. Map เข้า Models
	var projects []models.Project
	for _, item := range result.Items {
		projects = append(projects, models.Project{
			ProjectID: fmt.Sprintf("%d", item.ID),
			RepoName:  item.Name,
			Owner:     item.Owner.Login,
			RepoURL:   item.HTMLURL,
			Stars:     item.StargazersCount,
			Language:  item.Language,
			Status:    "active",
		})
	}

	return projects, nil
}