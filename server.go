package main

import (
	"log"
	"vuln-scanner/internal/database"
	"vuln-scanner/internal/models"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// StartServer : ฟังก์ชันหลักสำหรับเริ่ม API Server
func StartServer() {
	r := gin.Default()

	// 1. ตั้งค่า CORS (อนุญาตให้ Frontend Port 5173 เชื่อมต่อได้)
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173", "http://127.0.0.1:5173"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
		AllowHeaders:     []string{"Origin", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	// --- 🟢 GROUP 1: BASIC DATA (ข้อมูลพื้นฐาน) ---

	// API: ดึงสถิติรวม (Total Projects / Total Vulns)
	r.GET("/api/stats", func(c *gin.Context) {
		var projectCount int64
		var vulnCount int64
		database.DB.Model(&models.Project{}).Count(&projectCount)
		database.DB.Model(&models.Finding{}).Count(&vulnCount)
		c.JSON(200, gin.H{"total_projects": projectCount, "total_vulns": vulnCount})
	})

	// API: ดึงรายชื่อภาษาทั้งหมด (สำหรับ Dropdown)
	r.GET("/api/options/languages", func(c *gin.Context) {
		var langs []string
		database.DB.Model(&models.Project{}).
			Distinct("language").
			Where("language != ''").
			Order("language ASC").
			Pluck("language", &langs)
		c.JSON(200, langs)
	})

	// API: ค้นหาและกรอง Projects
	r.GET("/api/projects", func(c *gin.Context) {
		db := database.DB.Model(&models.Project{}).Preload("Commits")

		// Filter: Language
		if lang := c.Query("lang"); lang != "" {
			db = db.Where("language ILIKE ?", "%"+lang+"%")
		}
		// Filter: Stars
		if minStars := c.Query("min_stars"); minStars != "" {
			db = db.Where("stars >= ?", minStars)
		}
		if maxStars := c.Query("max_stars"); maxStars != "" {
			db = db.Where("stars <= ?", maxStars)
		}

		var projects []models.Project
		db.Order("stars DESC").Find(&projects)
		c.JSON(200, projects)
	})

	// API: เจาะลึกรายโปรเจกต์ (Project Details + Timeline)
	r.GET("/api/project/:id", func(c *gin.Context) {
		id := c.Param("id")
		var project models.Project

		// ดึง Project -> Commits -> Scans -> Findings
		err := database.DB.Preload("Commits.Scans.Findings").First(&project, "project_id = ?", id).Error
		
		if err != nil {
			c.JSON(404, gin.H{"error": "Project not found"})
			return
		}
		c.JSON(200, project)
	})

	// --- 🟡 GROUP 2: DASHBOARD ANALYTICS (กราฟหน้าแรก) ---

	// API: Dynamic Grouping & Filtering (กราฟแท่งหน้าแรก)
	r.GET("/api/analytics", func(c *gin.Context) {
		groupBy := c.DefaultQuery("group_by", "vulnerability_id")
		minStars := c.DefaultQuery("min_stars", "0")
		severities := c.QueryArray("severity")

		type StatResult struct {
			Name  string `json:"name"`
			Value int    `json:"value"`
		}
		var results []StatResult

		// Query แบบ Join 4 ตาราง
		query := database.DB.Table("findings").
			Joins("JOIN scans ON findings.scan_id = scans.scan_id").
			Joins("JOIN commits ON scans.commit_id = commits.commit_id").
			Joins("JOIN projects ON commits.project_id = projects.project_id").
			Where("projects.stars >= ?", minStars)

		if len(severities) > 0 {
			query = query.Where("findings.severity IN ?", severities)
		}

		// เลือก field ที่จะ Group By
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

	// --- 🔴 GROUP 3: DEEP DIVE ANALYTICS (หน้าวิเคราะห์ลึก) ---

	// API: The Matrix (Language vs Vulnerability)
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

	// API: Trends (แนวโน้มการเกิดช่องโหว่ตามเวลา)
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

	// API: Top Frequent vs Top Fixed (รายงานพิเศษ)
	r.GET("/api/report/vulnerabilities", func(c *gin.Context) {
		lang := c.Query("lang")
		mode := c.Query("mode") // frequent, fixed

		type RankResult struct {
			Name  string `json:"name"`
			Count int    `json:"count"`
		}
		var results []RankResult

		if mode == "fixed" {
			// Logic: เคยเจอในอดีต แต่ไม่เจอใน Commit ล่าสุด (หายไป = แก้แล้ว)
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
				ORDER BY count DESC
				LIMIT 10;
			`
			database.DB.Raw(sql, lang, lang).Scan(&results)
		} else {
			// Logic: เจอบ่อยสุด (นับดื้อๆ)
			database.DB.Table("findings").
				Select("findings.vulnerability_id as name, COUNT(*) as count").
				Joins("JOIN scans ON findings.scan_id = scans.scan_id").
				Joins("JOIN commits ON scans.commit_id = commits.commit_id").
				Joins("JOIN projects ON commits.project_id = projects.project_id").
				Where("projects.language = ?", lang).
				Group("findings.vulnerability_id").
				Order("count DESC").
				Limit(10).
				Scan(&results)
		}

		c.JSON(200, results)
	})

	// ------------------------------------------
	log.Println("🚀 Server running on http://localhost:8081")
	if err := r.Run(":8081"); err != nil {
		log.Fatal("❌ Server failed to start:", err)
	}
}