package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"

	"vuln-scanner/internal/database"
	"vuln-scanner/internal/models"
	"vuln-scanner/internal/services"

	"github.com/joho/godotenv"
	"gorm.io/gorm/clause"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not found")
	}
	database.ConnectDB()

	fmt.Println("     Vulnerability Scanner & Dashboard   ")
	fmt.Println("==========================================")
	fmt.Println("1.Run Scanner")
	fmt.Println("2.Dashboard")
	fmt.Print("\nSelect 1 or 2: ")

	reader := bufio.NewReader(os.Stdin)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	if choice == "2" {
		fmt.Println("\nStarting Web Server...")
		StartServer()
	} else {
		runScanner(reader)
	}
}

func runScanner(reader *bufio.Reader) {
	fmt.Println("\nVulnerability Deep Miner")

	fmt.Print("1. Language (e.g. Go, Python, empty for all): ")
	lang, _ := reader.ReadString('\n')
	lang = strings.TrimSpace(lang)

	fmt.Print("2. Minimum Stars (e.g. 100): ")
	minStr, _ := reader.ReadString('\n')
	minStr = strings.TrimSpace(minStr)
	var minStars int
	if minStr == "" {
		minStars = 0
	} else {
		minStars, _ = strconv.Atoi(minStr)
	}

	fmt.Print("3. Maximum Stars (Press Enter for No Limit): ")
	maxStr, _ := reader.ReadString('\n')
	maxStr = strings.TrimSpace(maxStr)
	var maxStars int
	if maxStr == "" {
		maxStars = 0
	} else {
		maxStars, _ = strconv.Atoi(maxStr)
	}

	fmt.Print("4. New Repos to find: ")
	limitStr, _ := reader.ReadString('\n')
	targetCount, _ := strconv.Atoi(strings.TrimSpace(limitStr))
	if targetCount == 0 {
		targetCount = 1
	}

	fmt.Printf("\nSearching GitHub...\n")

	projects, err := services.SearchRepositories(lang, minStars, maxStars, targetCount)
	if err != nil {
		log.Fatalf("❌ Search Error: %v", err)
	}

	if len(projects) == 0 {
		fmt.Println("\nNo NEW repositories found in this batch.")
		return
	}

	fmt.Printf("✅ Found %d NEW repositories ready to scan!\n", len(projects))

	var targetsToScan []models.Project

	for _, project := range projects {
		database.DB.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "project_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"stars", "updated_at"}),
		}).Save(&project)

		targetsToScan = append(targetsToScan, project)
	}

	// อ่านค่าจาก .env
	maxWorkersStr := os.Getenv("MAX_CONCURRENT_SCANS")
	maxWorkers, err := strconv.Atoi(maxWorkersStr)
	if err != nil || maxWorkers < 1 {
		maxWorkers = 1 // ค่าเริ่มต้น
	}

	fmt.Printf("\nStarting Concurrent Scans (Max %d workers) for %d repositories...\n", maxWorkers, len(targetsToScan))

	var wg sync.WaitGroup
	// ใช้ Channel เป็น Semaphore เพื่อจำกัดจำนวนการทำงานพร้อมกัน
	sem := make(chan struct{}, maxWorkers)

	for i, project := range targetsToScan {
		wg.Add(1)

		// ส่งงานเข้า Goroutine
		go func(p models.Project, index int) {
			defer wg.Done() // แจ้ง WaitGroup ว่าเสร็จแล้ว

			sem <- struct{}{} // ขอโควต้าการทำงาน

			// คืนโควต้าเมื่อเสร็จงาน
			defer func() { <-sem }()

			fmt.Printf("\n   ⏳ [%d/%d] Starting Scan: %s/%s\n", index+1, len(targetsToScan), p.Owner, p.RepoName)

			// เริ่มสแกน
			services.ProcessRepositoryHistory(p)

			fmt.Printf("\n   ✅ Finished Scan: %s/%s\n", p.Owner, p.RepoName)
		}(project, i)
	}

	wg.Wait()

	fmt.Println("\n🎉 Mission Complete! All repositories have been scanned.")
	fmt.Println("You can now start the dashboard (Option 2) to view results.")
}
