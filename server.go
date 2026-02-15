package main

import (
	"log"
	"vuln-scanner/internal/database"
	"vuln-scanner/internal/models"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func StartServer() {
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173", "http://127.0.0.1:5173"},
		AllowMethods:     []string{"GET", "POST"},
		AllowHeaders:     []string{"Origin", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	// API 1: Stats รวม
	r.GET("/api/stats", func(c *gin.Context) {
		var projectCount int64
		var vulnCount int64
		database.DB.Model(&models.Project{}).Count(&projectCount)
		database.DB.Model(&models.Finding{}).Count(&vulnCount)
		c.JSON(200, gin.H{"total_projects": projectCount, "total_vulns": vulnCount})
	})

	// API 2: รายชื่อโปรเจกต์ (พร้อม Filter: Language, Stars Max/Min)
	r.GET("/api/projects", func(c *gin.Context) {
		db := database.DB.Model(&models.Project{}).Preload("Commits")

		// --- Filter Logic ---
		lang := c.Query("lang")
		if lang != "" {
			db = db.Where("language ILIKE ?", "%"+lang+"%")
		}

		minStars := c.Query("min_stars")
		if minStars != "" {
			db = db.Where("stars >= ?", minStars)
		}

		maxStars := c.Query("max_stars")
		if maxStars != "" {
			db = db.Where("stars <= ?", maxStars)
		}
		// ---------------------

		var projects []models.Project
		db.Order("stars DESC").Find(&projects)
		c.JSON(200, projects)
	})

	// API 3: เจาะลึกรายโปรเจกต์ (Project Details)
	// ดึง Commit -> Scan -> Findings เพื่อดูว่าแก้อะไรไปบ้าง
	r.GET("/api/project/:id", func(c *gin.Context) {
		id := c.Param("id")
		var project models.Project

		// ดึงข้อมูลลูก-หลาน-เหลน (Project -> Commits -> Scans -> Findings)
		err := database.DB.Preload("Commits.Scans.Findings").First(&project, "project_id = ?", id).Error
		
		if err != nil {
			c.JSON(404, gin.H{"error": "Project not found"})
			return
		}
		c.JSON(200, project)
	})

	log.Println("🚀 Server running on http://localhost:8081")
	r.Run(":8081")
}