package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"vuln-scanner/internal/database"
	"vuln-scanner/internal/models"
	"vuln-scanner/internal/services"

	"github.com/joho/godotenv"
	"gorm.io/gorm/clause"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("⚠️  Warning: .env file not found")
	}
	database.ConnectDB()

	fmt.Println("     Vulnerability Scanner & Dashboard   ")
	fmt.Println("==========================================")
	fmt.Println("1.  Run Scanner (Deep Mining)")
	fmt.Println("2.  Start Web Server (Dashboard)")
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
	fmt.Println("\nGitHub Vulnerability Deep Miner")

	fmt.Print("1. Language (e.g. Go, Python, empty for all): ")
	lang, _ := reader.ReadString('\n')
	lang = strings.TrimSpace(lang)

	fmt.Print("2. Minimum Stars (e.g. 100): ")
	minStr, _ := reader.ReadString('\n')
	minStars, _ := strconv.Atoi(strings.TrimSpace(minStr))

	fmt.Print("3. Maximum Stars (Press Enter for No Limit): ")
	maxStr, _ := reader.ReadString('\n')
	maxStars, _ := strconv.Atoi(strings.TrimSpace(maxStr))

	fmt.Print("4. New Repos to find: ")
	limitStr, _ := reader.ReadString('\n')
	targetCount, _ := strconv.Atoi(strings.TrimSpace(limitStr)) // จำนวนเป้าหมายที่ต้องการ
	if targetCount == 0 { targetCount = 1 }

	fmt.Printf("\nSearching GitHub...\n")
	
	fetchBuffer := targetCount + 50 
	if fetchBuffer > 100 { fetchBuffer = 100 } // GitHub API จำกัด per_page สูงสุดที่ 100

	projects, err := services.SearchRepositories(lang, minStars, maxStars, fetchBuffer)
	if err != nil {
		log.Fatalf("Search Error: %v", err)
	}

	fmt.Printf("Fetched top %d candidates to find %d new repositories...\n", len(projects), targetCount)

	processedCount := 0 // ตัวนับจำนวนที่ทำสำเร็จ

	for _, project := range projects {
		// ถ้าครบตามเป้าหมายแล้ว ให้หยุดทันที
		if processedCount >= targetCount {
			break
		}

		fmt.Printf("\nChecking candidate: %s/%s (%0.f)\n", project.Owner, project.RepoName, project.Stars)

		// 1. เช็คว่ามีใน DB หรือยัง
		var count int64
		database.DB.Model(&models.Project{}).Where("repo_url = ?", project.RepoURL).Count(&count)
		
		if count > 0 {
			// เจอซ้ำ -> ข้ามเงียบๆ หรือบอกสั้นๆ
			fmt.Print("Exists in DB. Skipping next...\r") // ใช้ \r เพื่อทับบรรทัดเดิมจะได้ไม่รก
			continue 
		}

		// 2. ถ้าเป็นตัวใหม่ -> เริ่มกระบวนการ
		fmt.Println("\nNEW TARGET FOUND Starting Deep Scan...")
		
		// Save Project
		database.DB.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "project_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"stars", "updated_at"}),
		}).Save(&project)

		// Start Scan
		services.ProcessRepositoryHistory(project)
		
		processedCount++ // นับเพิ่ม 1
		fmt.Printf("Progress: [%d/%d] New Repos Scanned\n", processedCount, targetCount)
	}

	if processedCount == 0 {
		fmt.Println("\nNo NEW repositories found in this batch.")
		fmt.Println("Try adjusting 'Min/Max Stars' to find a different set of projects.")
	} else {
		fmt.Println("\nMission Complete! Found and scanned", processedCount, "new repositories.")
	}
}