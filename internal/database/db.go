package database

import (
	"fmt"
	"log"
	"os"

	"vuln-scanner/internal/models" // <--- อย่าลืม import models

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

func ConnectDB() {
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=Asia/Bangkok",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_PORT"),
	)

	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})

if err != nil {
		log.Fatal("❌ Failed to connect to database:", err)
	}

	log.Println("✅ Database Connected Successfully via GORM!")

	log.Println("🔄 Running Auto Migrations...")
	err = DB.AutoMigrate(
		&models.Project{},             // 1. Projects
		&models.Commit{},              // 2. Commits
		&models.Scan{},                // 3. Scans (ที่หายไป)
		&models.Finding{},             // 4. Findings (ที่หายไป)
		&models.VulnerabilityDetail{}, // 5. Details
	)
	
	if err != nil {
		log.Fatal("❌ Migration Failed:", err)
	}
	
	log.Println("✅ Migration Completed!")
}