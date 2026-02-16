package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"vuln-scanner/internal/database"
	"vuln-scanner/internal/services"

	"github.com/joho/godotenv"
	"gorm.io/gorm/clause"
)

func main() {
	//โหลด Config - ต่อ Database
	if err := godotenv.Load(); err != nil {
		log.Println("⚠️  Warning: .env file not found")
	}
	database.ConnectDB()

	//แสดงเมนูเลือกโหมด
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

//รันระบบสแกน
func runScanner(reader *bufio.Reader) {
	fmt.Println("\n🔎 === GitHub Vulnerability Deep Miner (Auto-Sampling) ===")

	// รับเงื่อนไขการกรอง Repo
	fmt.Print("1. Language (e.g. Go, Python, empty for all): ")
	lang, _ := reader.ReadString('\n')
	lang = strings.TrimSpace(lang)

	fmt.Print("2. Minimum Stars: ")
	starsStr, _ := reader.ReadString('\n')
	minStars, _ := strconv.Atoi(strings.TrimSpace(starsStr))

	fmt.Print("3. Max Repos to find: ")
	limitStr, _ := reader.ReadString('\n')
	repoLimit, _ := strconv.Atoi(strings.TrimSpace(limitStr))
	if repoLimit == 0 {
		repoLimit = 1
	}

	// เริ่มค้นหา Repositories
	fmt.Printf("\n📡 Searching GitHub...")
	projects, err := services.SearchRepositories(lang, minStars, repoLimit)
	if err != nil {
		log.Fatalf("❌ Search Error: %v", err)
	}

	fmt.Printf("🎯 Found %d repositories.\n", len(projects))

	// ลูปสแกนแต่ละโปรเจกต์
	for i, project := range projects {
		fmt.Printf("\n["+strconv.Itoa(i+1)+"/"+strconv.Itoa(len(projects))+"] 🚀 Processing: %s/%s\n", project.Owner, project.RepoName)

		// บันทึก Project ลง DB
		database.DB.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "project_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"stars", "updated_at"}),
		}).Save(&project)

		// เรียกใช้ Deep Scan (แบบ Sampling หาร 10)
		services.ProcessRepositoryHistory(project)
	}

	fmt.Println("\nDeep Mining Completed")
}