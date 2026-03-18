package services

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
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
	var newProjects []models.Project
	currentMaxStars := maxStars

	// สไลด์ช่วงดาวไปเรื่อยๆ จนกว่าจะครบ
	for len(newProjects) < targetNewCount {

		// สร้าง Query String สำหรับรอบนี้
		starQuery := fmt.Sprintf(">=%d", minStars)
		if currentMaxStars > 0 {
			starQuery = fmt.Sprintf("%d..%d", minStars, currentMaxStars)
		}

		query := fmt.Sprintf("stars:%s", starQuery)
		if lang != "" {
			query += fmt.Sprintf(" language:%s", lang)
		}

		page := 1
		perPage := 100
		var lastStarCount float64 = -1
		gotItemsInThisQuery := false

		fmt.Printf("\n📡 GitHub Query: %s (Target NEW: %d repos)\n", query, targetNewCount)

		// ดึงทีละหน้า (หน้าละ 100) จนกว่าจะชนลิมิต 1,000
		for {
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

			// ดักจับ Rate Limit 403 (พัก 60 วินาที)
			if resp.StatusCode == 403 {
				fmt.Println("\nโควต้า GitHub API เต็ม!")
				fmt.Println("หลับ 60 วินาที")
				resp.Body.Close()
				time.Sleep(60 * time.Second)
				continue // วนกลับไปยิง API ดึงหน้าเดิมซ้ำ
			} else if resp.StatusCode == 422 {
				// ดักจับ 422
				fmt.Printf("\nครบ 1000 ตัวของช่วงนี้ (หน้า %d)\n", page)
				resp.Body.Close()
				break // สั่งหยุดลูปหน้าเพจ เพื่อไปสไลด์ลดเพดานดาวในลูปชั้นนอก
			} else if resp.StatusCode != 200 {
				resp.Body.Close()
				return nil, fmt.Errorf("GitHub API Error: %s", resp.Status)
			}

			var result GitHubSearchResponse
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				resp.Body.Close()
				return nil, err
			}
			resp.Body.Close()

			if len(result.Items) == 0 {
				break // GitHub สำหรับช่วงดาวนี้แล้วหมด
			}

			gotItemsInThisQuery = true
			fmt.Printf("   📥 Fetched page %d (%d items). Filtering existing...\n", page, len(result.Items))

			// ตรวจสอบว่ามีใน DB หรือยัง
			for _, item := range result.Items {
				// จำดาวของโปรเจกต์ล่าสุด
				lastStarCount = item.StargazersCount 

				var count int64
				database.DB.Model(&models.Project{}).Where("repo_url = ?", item.HTMLURL).Count(&count)

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

					if len(newProjects) >= targetNewCount {
						break // ได้ครบเป้าหมายแล้ว
					}
				}
			}

			if len(newProjects) >= targetNewCount {
				break
			}

			page++
			time.Sleep(2500 * time.Millisecond) // หน่วงเวลากันโดนแบน
		}

		// ถ้าได้ครบตามจำนวนเป้าหมายแล้ว
		if len(newProjects) >= targetNewCount {
			break
		}

		// ถ้าไม่เจออะไรเลย = หมดของทั้งระบบ GitHub แล้ว
		if !gotItemsInThisQuery {
			fmt.Println("\nหมดGitHub สำหรับภาษานี้")
			break
		}

		//  หาช่วงต่อไป!
		if lastStarCount != -1 {
			nextMax := int(lastStarCount)
			
			// ถ้าเพดานดาวชนกับขั้นต่ำแล้ว
			if nextMax < minStars {
				fmt.Println("\nสุดขอบเขต Min Stars")
				break
			}

			// กันกรณีมีโปรเจกต์ดาว ... เป๊ะๆ เกินพัน
			if currentMaxStars > 0 && nextMax >= currentMaxStars {
				nextMax = currentMaxStars - 1
			}
			
			currentMaxStars = nextMax
			fmt.Printf("🔄 เลื่อนเพดานดาวลงมาหาต่อที่: Max %d Stars\n", currentMaxStars)
		} else {
			break
		}

	}

	return newProjects, nil
}