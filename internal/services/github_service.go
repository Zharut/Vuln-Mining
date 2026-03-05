package services

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"vuln-scanner/internal/database"
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

func SearchRepositories(lang string, minStars int, maxStars int, targetNewCount int) ([]models.Project, error) {
	// 1. สร้าง Query String
	starQuery := fmt.Sprintf(">=%d", minStars)
	if maxStars > 0 {
		starQuery = fmt.Sprintf("%d..%d", minStars, maxStars)
	}

	query := fmt.Sprintf("stars:%s", starQuery)
	if lang != "" {
		query += fmt.Sprintf(" language:%s", lang)
	}

	var newProjects []models.Project
	page := 1
	perPage := 100

	fmt.Printf("📡 GitHub Query: %s (Target NEW: %d repos)\n", query, targetNewCount)

	// 2. ลูปดึงข้อมูลจนกว่าจะได้ครบ
	for len(newProjects) < targetNewCount {
		url := fmt.Sprintf("https://api.github.com/search/repositories?q=%s&sort=stars&order=desc&per_page=%d&page=%d", query, perPage, page)
		
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}

		req.Header.Set("Accept", "application/vnd.github.v3+json")
		req.Header.Set("User-Agent", "Vuln-Scanner-App")
		
		token := os.Getenv("GITHUB_TOKEN")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != 200 {
			resp.Body.Close()
			return nil, fmt.Errorf("GitHub API Error: %s (Check rate limit or token)", resp.Status)
		}

		var result GitHubSearchResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			return nil, err
		}
		resp.Body.Close()

		if len(result.Items) == 0 {
			break // API หมดสต๊อก หาเพิ่มไม่ได้
		}

		fmt.Printf("   📥 Fetched page %d (%d items). Filtering existing...\n", page, len(result.Items))

		// 3. ตรวจสอบว่ามีใน DB หรือยัง
		for _, item := range result.Items {
			var count int64
			database.DB.Model(&models.Project{}).Where("repo_url = ?", item.HTMLURL).Count(&count)

			// ถ้า count = 0 แปลว่าไม่เคยมีใน DB มาก่อน
			if count == 0 {
				newProjects = append(newProjects, models.Project{
					ProjectID: fmt.Sprintf("%d", item.ID),
					RepoName:  item.Name,
					Owner:     item.Owner.Login,
					RepoURL:   item.HTMLURL,
					Stars:     item.StargazersCount,
					Language:  item.Language,
					Status:    "active",
				})

				// ครบเป้าหมาย หยุด
				if len(newProjects) >= targetNewCount {
					break
				}
			}
		}

		page++
	}

	return newProjects, nil
}
