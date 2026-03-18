package main

import (
	"io"
	"log"
	"net/http"
	"vuln-scanner/internal/database"
	"vuln-scanner/internal/models"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func StartServer() {
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173", "http://127.0.0.1:5173"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
		AllowHeaders:     []string{"Origin", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	r.GET("/api/stats", func(c *gin.Context) {
		var projectCount int64
		var vulnCount int64
		database.DB.Model(&models.Project{}).Count(&projectCount)
		database.DB.Model(&models.Finding{}).Count(&vulnCount)
		c.JSON(200, gin.H{"total_projects": projectCount, "total_vulns": vulnCount})
	})

	r.GET("/api/options/languages", func(c *gin.Context) {
		var rawLangs []string
		
		database.DB.Model(&models.Project{}).
			Distinct("language").
			Order("language ASC").
			Pluck("language", &rawLangs)

		// ค่าว่างให้กลายเป็นคำว่า "Misc"
		var finalLangs []string
		hasMisc := false

		for _, l := range rawLangs {
			if l == "" || l == " " {
				if !hasMisc {
					finalLangs = append(finalLangs, "Misc")
					hasMisc = true
				}
			} else {
				finalLangs = append(finalLangs, l)
			}
		}

		c.JSON(200, finalLangs)
	})

	r.GET("/api/projects", func(c *gin.Context) {
		db := database.DB.Model(&models.Project{}).Preload("Commits")
		if lang := c.Query("lang"); lang != "" {
			db = db.Where("language ILIKE ?", "%"+lang+"%")
		}
		if minStars := c.Query("min_stars"); minStars != "" {
			db = db.Where("stars >= ?", minStars)
		}
		var projects []models.Project
		db.Order("stars DESC").Find(&projects)
		c.JSON(200, projects)
	})

	r.GET("/api/project/:id", func(c *gin.Context) {
		id := c.Param("id")
		var project models.Project
		err := database.DB.Preload("Commits.Scans.Findings").First(&project, "project_id = ?", id).Error
		if err != nil {
			c.JSON(404, gin.H{"error": "Project not found"})
			return
		}
		c.JSON(200, project)
	})

	r.GET("/api/analytics", func(c *gin.Context) {
		groupBy := c.DefaultQuery("group_by", "vulnerability_id")
		minStars := c.DefaultQuery("min_stars", "0")
		severities := c.QueryArray("severity")

		type StatResult struct {
			Name  string `json:"name"`
			Value int    `json:"value"`
		}
		var results []StatResult

		query := database.DB.Table("findings").
			Joins("JOIN scans ON findings.scan_id = scans.scan_id").
			Joins("JOIN commits ON scans.commit_id = commits.commit_id").
			Joins("JOIN projects ON commits.project_id = projects.project_id").
			Where("projects.stars >= ?", minStars)

		if len(severities) > 0 {
			query = query.Where("findings.severity IN ?", severities)
		}

		dbField := "findings.vulnerability_id"
		switch groupBy {
		case "language":
			dbField = "projects.language"
		case "tool":
			dbField = "findings.tool"
		case "severity":
			dbField = "findings.severity"
		}

		query.Select(dbField + " as name, COUNT(*) as value").
			Group(dbField).
			Order("value DESC").
			Scan(&results)

		c.JSON(200, results)
	})

	r.GET("/api/matrix", func(c *gin.Context) {
		xAxis := c.DefaultQuery("x_axis", "language")
		yAxis := c.DefaultQuery("y_axis", "severity")

		type MatrixPoint struct {
			X     string `json:"x"`
			Y     string `json:"y"`
			Count int    `json:"count"`
		}
		var results []MatrixPoint

		fieldMap := map[string]string{
			"language":         "projects.language",
			"vulnerability_id": "findings.vulnerability_id",
			"severity":         "findings.severity",
			"tool":             "findings.tool",
		}
		xField := fieldMap[xAxis]
		yField := fieldMap[yAxis]

		database.DB.Table("findings").
			Select(xField + " as x, " + yField + " as y, COUNT(*) as count").
			Joins("JOIN scans ON findings.scan_id = scans.scan_id").
			Joins("JOIN commits ON scans.commit_id = commits.commit_id").
			Joins("JOIN projects ON commits.project_id = projects.project_id").
			Where(xField + " != '' AND " + yField + " != ''").
			Group(xField + ", " + yField).
			Order("count DESC").
			Limit(200).
			Scan(&results)

		c.JSON(200, results)
	})

	r.GET("/api/trends", func(c *gin.Context) {
		lang := c.Query("lang")
		type TrendPoint struct {
			CommitDate string `json:"date"`
			VulnCount  int    `json:"count"`
			RepoName   string `json:"repo"`
		}
		var trends []TrendPoint

		query := database.DB.Table("scans").
			Select("TO_CHAR(commits.committed_at, 'YYYY-MM-DD') as date, projects.repo_name as repo, COUNT(findings.finding_id) as count").
			Joins("JOIN commits ON scans.commit_id = commits.commit_id").
			Joins("JOIN projects ON commits.project_id = projects.project_id").
			Joins("LEFT JOIN findings ON scans.scan_id = findings.scan_id")

		if lang != "" {
			query = query.Where("projects.language = ?", lang)
		}
		query.Group("projects.repo_name, commits.committed_at").
			Order("commits.committed_at ASC").
			Scan(&trends)
		c.JSON(200, trends)
	})

	r.GET("/api/report/vulnerabilities", func(c *gin.Context) {
		lang := c.Query("lang")
		mode := c.Query("mode")

		type RankResult struct {
			Name  string `json:"name"`
			Count int    `json:"count"`
		}
		var results []RankResult

		if mode == "fixed" {
			if lang == "Misc" {
				// กรณีเป็น ไม่มีภาษา
				sql := `
					WITH AllFindings AS (
						SELECT p.project_id, f.vulnerability_id
						FROM findings f
						JOIN scans s ON f.scan_id = s.scan_id
						JOIN commits c ON s.commit_id = c.commit_id
						JOIN projects p ON c.project_id = p.project_id
						WHERE p.language = '' OR p.language IS NULL
						GROUP BY p.project_id, f.vulnerability_id
					),
					CurrentFindings AS (
						SELECT p.project_id, f.vulnerability_id
						FROM findings f
						JOIN scans s ON f.scan_id = s.scan_id
						JOIN commits c ON s.commit_id = c.commit_id
						JOIN projects p ON c.project_id = p.project_id
						WHERE (p.language = '' OR p.language IS NULL)
						  AND c.committed_at = (SELECT MAX(committed_at) FROM commits WHERE project_id = p.project_id)
					)
					SELECT a.vulnerability_id as name, COUNT(*) as count
					FROM AllFindings a
					LEFT JOIN CurrentFindings cur 
						ON a.project_id = cur.project_id AND a.vulnerability_id = cur.vulnerability_id
					WHERE cur.project_id IS NULL 
					GROUP BY a.vulnerability_id
					ORDER BY count DESC;
				`
				database.DB.Raw(sql).Scan(&results)
			} else {
				// ภาษาปกติ
				sql := `
					WITH AllFindings AS (
						SELECT p.project_id, f.vulnerability_id
						FROM findings f
						JOIN scans s ON f.scan_id = s.scan_id
						JOIN commits c ON s.commit_id = c.commit_id
						JOIN projects p ON c.project_id = p.project_id
						WHERE p.language = ?
						GROUP BY p.project_id, f.vulnerability_id
					),
					CurrentFindings AS (
						SELECT p.project_id, f.vulnerability_id
						FROM findings f
						JOIN scans s ON f.scan_id = s.scan_id
						JOIN commits c ON s.commit_id = c.commit_id
						JOIN projects p ON c.project_id = p.project_id
						WHERE p.language = ?
						  AND c.committed_at = (SELECT MAX(committed_at) FROM commits WHERE project_id = p.project_id)
					)
					SELECT a.vulnerability_id as name, COUNT(*) as count
					FROM AllFindings a
					LEFT JOIN CurrentFindings cur 
						ON a.project_id = cur.project_id AND a.vulnerability_id = cur.vulnerability_id
					WHERE cur.project_id IS NULL 
					GROUP BY a.vulnerability_id
					ORDER BY count DESC;
				`
				database.DB.Raw(sql, lang, lang).Scan(&results)
			}

		} else {
			// Frequent (ใช้ GORM)
			query := database.DB.Table("findings").
				Select("findings.vulnerability_id as name, COUNT(*) as count").
				Joins("JOIN scans ON findings.scan_id = scans.scan_id").
				Joins("JOIN commits ON scans.commit_id = commits.commit_id").
				Joins("JOIN projects ON commits.project_id = projects.project_id")

			// กรองตามภาษา
			if lang == "Misc" {
				query = query.Where("projects.language = ? OR projects.language IS NULL", "")
			} else if lang != "" && lang != "All" {
				query = query.Where("projects.language = ?", lang)
			}

			query.Group("findings.vulnerability_id").
				Order("count DESC").
				Scan(&results)
		}

		c.JSON(200, results)
	})

	// MTTR
	r.GET("/api/report/mttr", func(c *gin.Context) {
		type MTTRResult struct {
			Language     string  `json:"language"`
			VulnID       string  `json:"vulnerability_id"`
			AvgDaysToFix float64 `json:"avg_days_to_fix"`
		}
		var results []MTTRResult

		sql := `
			WITH VulnLifespan AS (
				SELECT 
					p.language, 
					f.vulnerability_id, 
					p.project_id,
					MIN(c.committed_at) as first_seen,
					MAX(c.committed_at) as last_seen
				FROM findings f
				JOIN scans s ON f.scan_id = s.scan_id
				JOIN commits c ON s.commit_id = c.commit_id
				JOIN projects p ON c.project_id = p.project_id
				GROUP BY p.language, f.vulnerability_id, p.project_id
			),
			CurrentVulns AS (
				SELECT DISTINCT p.project_id, f.vulnerability_id
				FROM findings f
				JOIN scans s ON f.scan_id = s.scan_id
				JOIN commits c ON s.commit_id = c.commit_id
				JOIN projects p ON c.project_id = p.project_id
				WHERE c.committed_at = (SELECT MAX(committed_at) FROM commits WHERE project_id = p.project_id)
			)
			SELECT 
				COALESCE(vl.language, 'Misc') as language,
				vl.vulnerability_id,
				AVG(EXTRACT(EPOCH FROM (vl.last_seen - vl.first_seen))/86400) as avg_days_to_fix
			FROM VulnLifespan vl
			LEFT JOIN CurrentVulns cv 
				ON vl.project_id = cv.project_id AND vl.vulnerability_id = cv.vulnerability_id
			WHERE cv.project_id IS NULL 
			  AND vl.last_seen > vl.first_seen 
			GROUP BY vl.language, vl.vulnerability_id
			ORDER BY avg_days_to_fix DESC
			LIMIT 50;
		`

		database.DB.Raw(sql).Scan(&results)
		c.JSON(200, results)
	})

	// ฟังก์ชันช่วยยิง Request
	fetchWithUA := func(url string) (*http.Response, error) {
		client := &http.Client{}
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		//User-Agent
		req.Header.Set("User-Agent", "VulnScanner-Student-Project/1.0")
		return client.Do(req)
	}

	// Proxy สำหรับดึง CVE
	r.GET("/api/proxy/cve/:id", func(c *gin.Context) {
		id := c.Param("id")

		//ดึงจาก cve.circl.lu
		resp, err := fetchWithUA("https://cve.circl.lu/api/cve/" + id)
		if err == nil && resp.StatusCode == 200 {
			defer resp.Body.Close()

			c.Status(resp.StatusCode)
			io.Copy(c.Writer, resp.Body)
			return
		}
		c.JSON(404, gin.H{"error": "CVE not found in external databases"})
	})

	// Proxy สำหรับดึง GHSA
	r.GET("/api/proxy/ghsa/:id", func(c *gin.Context) {
		id := c.Param("id")
		resp, err := fetchWithUA("https://api.osv.dev/v1/vulns/" + id)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to fetch"})
			return
		}
		defer resp.Body.Close()
		c.Status(resp.StatusCode)
		io.Copy(c.Writer, resp.Body)
	})

	// failsafe ดึงจาก sql
	r.GET("/api/knowledge/:id", func(c *gin.Context) {
		id := c.Param("id")
		
		type VulnDetail struct {
			VulnerabilityID string  `json:"vulnerability_id"`
			Title           string  `json:"title"`
			Description     string  `json:"description"`
			Remediation     string  `json:"remediation"`
			CvssScore       float64 `json:"cvss_score"`
			ReferencesJSON  string  `json:"references_json"`
		}
		var detail VulnDetail

		if err := database.DB.Table("vulnerability_details").Where("vulnerability_id = ?", id).First(&detail).Error; err != nil {
			c.JSON(404, gin.H{"error": "Not found in local DB"})
			return
		}
		c.JSON(200, detail)
	})

	log.Println("Server running on http://localhost:8081")
	if err := r.Run(":8081"); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}