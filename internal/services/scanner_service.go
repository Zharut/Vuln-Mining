package services

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"sync"

	"vuln-scanner/internal/database"
	"vuln-scanner/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm/clause"
)

type SemgrepOutput struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct{ Line int `json:"line"` } `json:"start"`
		Extra   struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
			Metadata struct{ CWE []string `json:"cwe"` } `json:"metadata"`
		} `json:"extra"`
	} `json:"results"`
}

type TrivyOutput struct {
	Results []struct {
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID  string   `json:"VulnerabilityID"`
			PkgName          string   `json:"PkgName"`
			InstalledVersion string   `json:"InstalledVersion"`
			FixedVersion     string   `json:"FixedVersion"`
			Title            string   `json:"Title"`
			Description      string   `json:"Description"`
			Severity         string   `json:"Severity"`
			CweIDs           []string `json:"CweIDs"`
			References       []string `json:"References"` 
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

type GitleaksResult struct {
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	File        string `json:"File"`
	RuleID      string `json:"RuleID"`
	Secret      string `json:"Secret"`
}

type CheckovOutput []struct {
	CheckType string `json:"check_type"`
	Results   struct {
		FailedChecks []struct {
			CheckID       string `json:"check_id"`
			CheckName     string `json:"check_name"`
			FilePath      string `json:"file_path"`
			FileLineRange []int  `json:"file_line_range"`
			Severity      string `json:"severity"`
			Guideline     string `json:"guideline"`
		} `json:"failed_checks"`
	} `json:"results"`
}

func saveVulnDetail(id, title, desc, remediation string, score float64, refs []string) {
	refJson, _ := json.Marshal(refs)
	if len(refs) == 0 {
		refJson = []byte("[]")
	}

	detail := models.VulnerabilityDetail{
		VulnerabilityID: id,
		Title:           title,
		Description:     desc,
		Remediation:     remediation,
		CvssScore:       score,
		ReferencesJSON:  string(refJson),
	}

	// Upsert ลง DB
	database.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "vulnerability_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"title", "description", "remediation", "references_json"}),
	}).Create(&detail)
}

func GetAllCommits(repoPath string) ([]models.Commit, error) {
	cmd := exec.Command("git", "log", "--reverse", "--format=%H|%an|%cd|%s", "--date=iso")
	cmd.Dir = repoPath
	output, err := cmd.StdoutPipe()
	if err != nil { return nil, err }
	if err := cmd.Start(); err != nil { return nil, err }

	var commits []models.Commit
	scanner := bufio.NewScanner(output)
	buf := make([]byte, 0, 10*1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "|")
		if len(parts) >= 4 {
			t, _ := time.Parse("2006-01-02 15:04:05 -0700", parts[2])
			c := models.Commit{
				CommitID:    uuid.New().String(),
				CommitHash:  parts[0],
				AuthorName:  parts[1],
				CommittedAt: t,
				Message:     parts[3],
				Branch:      "main",
			}
			commits = append(commits, c)
		}
	}
	cmd.Wait()
	return commits, nil
}

func runSemgrep(repoPath string, scanID string) ([]models.Finding, error) {
	var findings []models.Finding
	outFile := filepath.Join(repoPath, "semgrep.json")
	
	err := exec.Command("semgrep", "scan", "--config=auto", "--json", "--output="+outFile, ".").Run()
	if err != nil && !strings.Contains(err.Error(), "exit status 1") {}

	if data, err := os.ReadFile(outFile); err == nil {
		var out SemgrepOutput
		json.Unmarshal(data, &out)
		for _, r := range out.Results {
			cwe := "UNKNOWN"
			if len(r.Extra.Metadata.CWE) > 0 { cwe = strings.Split(r.Extra.Metadata.CWE[0], ":")[0] }
			
			// Auto-Save Detail
			sevScore := 5.0
			if strings.ToUpper(r.Extra.Severity) == "ERROR" { sevScore = 8.0 }
			saveVulnDetail(r.CheckID, r.Extra.Message, r.Extra.Message, "Review and fix code logic.", sevScore, []string{})

			findings = append(findings, models.Finding{
				FindingID: uuid.New().String(), ScanID: scanID, Tool: "Semgrep",
				VulnerabilityID: r.CheckID, CweID: cwe, Severity: strings.ToUpper(r.Extra.Severity),
				FilePath: r.Path, LineNumber: r.Start.Line, Message: r.Extra.Message, Status: "open", FCreatedAt: time.Now(),
			})
		}
	}
	return findings, nil
}

func runTrivy(repoPath string, scanID string) ([]models.Finding, error) {
	var findings []models.Finding
	outFile := filepath.Join(repoPath, "trivy.json")

	if err := exec.Command("trivy", "fs", ".", "--format", "json", "--output", outFile).Run(); err != nil {
		return nil, err
	}

	if data, err := os.ReadFile(outFile); err == nil {
		var out TrivyOutput
		json.Unmarshal(data, &out)
		for _, res := range out.Results {
			for _, v := range res.Vulnerabilities {
				cwe := "UNKNOWN"
				if len(v.CweIDs) > 0 { cwe = v.CweIDs[0] }
				
				// Auto-Save Detail
				remediation := fmt.Sprintf("Upgrade %s to version %s", v.PkgName, v.FixedVersion)
				saveVulnDetail(v.VulnerabilityID, v.Title, v.Description, remediation, 7.0, v.References)

				msg := fmt.Sprintf("%s (%s) -> Fixed: %s | %s", v.PkgName, v.InstalledVersion, v.FixedVersion, v.Title)
				findings = append(findings, models.Finding{
					FindingID: uuid.New().String(), ScanID: scanID, Tool: "Trivy",
					VulnerabilityID: v.VulnerabilityID, CweID: cwe, Severity: strings.ToUpper(v.Severity),
					FilePath: res.Target, LineNumber: 0, Message: msg, Status: "open", FCreatedAt: time.Now(),
				})
			}
		}
	}
	return findings, nil
}

func runGitleaks(repoPath string, scanID string) ([]models.Finding, error) {
	var findings []models.Finding
	outFile := filepath.Join(repoPath, "gitleaks.json")

	exec.Command("gitleaks", "detect", "--source", ".", "--report-path", outFile, "--no-git").Run()

	if data, err := os.ReadFile(outFile); err == nil {
		var out []GitleaksResult
		json.Unmarshal(data, &out)
		for _, r := range out {
			// Auto-Save Detail
			saveVulnDetail(r.RuleID, r.Description, "Secret detected by Gitleaks. Hardcoded secrets pose a severe security risk.", "Revoke this secret immediately and rotate credentials.", 9.0, []string{"https://github.com/zricethezav/gitleaks"})

			secretSnippet := r.Secret
			if len(secretSnippet) > 10 { secretSnippet = secretSnippet[:10] + "..." }
			findings = append(findings, models.Finding{
				FindingID: uuid.New().String(), ScanID: scanID, Tool: "Gitleaks",
				VulnerabilityID: r.RuleID, CweID: "CWE-798", Severity: "CRITICAL",
				FilePath: r.File, LineNumber: r.StartLine, Message: fmt.Sprintf("%s (Match: %s)", r.Description, secretSnippet),
				Status: "open", FCreatedAt: time.Now(),
			})
		}
	}
	return findings, nil
}

func runCheckov(repoPath string, scanID string) ([]models.Finding, error) {
	var findings []models.Finding
	outFile := filepath.Join(repoPath, "checkov.json")

	cmd := exec.Command("checkov", "-d", ".", "--output", "json", "--output-file-path", ".")
	cmd.Dir = repoPath
	f, _ := os.Create(outFile)
	cmd.Stdout = f
	cmd.Run()
	f.Close()

	if data, err := os.ReadFile(outFile); err == nil {
		var out CheckovOutput
		if err := json.Unmarshal(data, &out); err == nil {
			for _, runner := range out {
				for _, r := range runner.Results.FailedChecks {
					
					// Auto-Save Detail
					saveVulnDetail(r.CheckID, r.CheckName, r.CheckName, "Refer to guideline: "+r.Guideline, 6.0, []string{r.Guideline})

					line := 0
					if len(r.FileLineRange) > 0 { line = r.FileLineRange[0] }
					sev := "FAILED"
					if r.Severity != "" { sev = strings.ToUpper(r.Severity) }
					findings = append(findings, models.Finding{
						FindingID: uuid.New().String(), ScanID: scanID, Tool: "Checkov",
						VulnerabilityID: r.CheckID, CweID: "N/A", Severity: sev,
						FilePath: strings.TrimPrefix(r.FilePath, "/"), LineNumber: line, Message: r.CheckName, Status: "open", FCreatedAt: time.Now(),
					})
				}
			}
		}
	}
	return findings, nil
}

func ProcessRepositoryHistory(project models.Project) {
	targetDir := filepath.Join("scanned_repos", project.RepoName)

	defer func() {
		fmt.Printf("\nCleaning up: %s\n", targetDir)
		os.RemoveAll(targetDir)
	}()

	// Clone/Pull
	if _, err := os.Stat(targetDir); os.IsNotExist(err) {
		fmt.Printf("⬇ Cloning %s...\n", project.RepoURL)
		if err := exec.Command("git", "clone", project.RepoURL, targetDir).Run(); err != nil {
			log.Printf("Clone Failed: %v\n", err)
			return
		}
	} else {
		exec.Command("git", "-C", targetDir, "pull").Run()
	}

	// Get Commits
	fmt.Println("Fetching history...")
	allCommits, err:= GetAllCommits(targetDir)
	if err != nil {
		log.Printf("Failed to get commits: %v\n", err)
		return
	}
	totalCommits := len(allCommits)
	fmt.Printf("Total Commits: %d\n", totalCommits)

	if totalCommits == 0 {
		fmt.Println("No commits found.")
		return
	}

	var selectedCommits []models.Commit
	step := totalCommits / 10
	if step < 1 { step = 1 }
	for i := 0; i < totalCommits; i += step {
		selectedCommits = append(selectedCommits, allCommits[i])
	}
	if len(selectedCommits) > 0 && selectedCommits[len(selectedCommits)-1].CommitHash != allCommits[totalCommits-1].CommitHash {
		selectedCommits = append(selectedCommits, allCommits[totalCommits-1])
	}

	fmt.Printf("Scanning %d snapshots with 4 Engines...\n", len(selectedCommits))

	// Loop Commits
	for i, commit := range selectedCommits {
		fmt.Printf("\n[%d/%d] Snapshot: %s\n", i+1, len(selectedCommits), commit.CommitHash[:7])

		// Checkout
		exec.Command("git", "-C", targetDir, "checkout", "-f", commit.CommitHash).Run()

		// Save
		commit.ProjectID = project.ProjectID
		database.DB.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "commit_hash"}},
			DoUpdates: clause.AssignmentColumns([]string{"message"}),
		}).Create(&commit)
		
		var dbCommit models.Commit
		database.DB.Where("commit_hash = ?", commit.CommitHash).First(&dbCommit)

		toolList := []string{"Semgrep", "Trivy", "Gitleaks", "Checkov"}
		
		var toolWg sync.WaitGroup // คุมคิว

		for _, toolName := range toolList {
			toolWg.Add(1)
			
			// แยก 4 Tools รัน
			go func(tName string) {
				defer toolWg.Done()

				scanID := uuid.New().String()
				scan := models.Scan{
					ScanID:     scanID,
					CommitID:   dbCommit.CommitID,
					ToolUsed:   tName,
					ScanStatus: "running",
					StartedAt:  time.Now(),
				}
				database.DB.Create(&scan)

				var findings []models.Finding
				var err error

				switch tName {
				case "Semgrep":
					findings, err = runSemgrep(targetDir, scanID)
				case "Trivy":
					findings, err = runTrivy(targetDir, scanID)
				case "Gitleaks":
					findings, err = runGitleaks(targetDir, scanID)
				case "Checkov":
					findings, err = runCheckov(targetDir, scanID)
				}

				scan.FinishedAt = time.Now()
				scan.ScanStatus = "completed"

				if err != nil {
					scan.LogOutput = fmt.Sprintf("Error: %v", err)
				} else {
					scan.LogOutput = fmt.Sprintf("Findings: %d", len(findings))
					if len(findings) > 0 {
						database.DB.CreateInBatches(findings, 100)
					}
				}
				database.DB.Save(&scan)
			}(toolName)
		}

		// รอเครื่องมือสแกน4อันเสร็จก่อนคอมมิตต่อไป
		toolWg.Wait()
		fmt.Printf("completed for snapshot %s\n", commit.CommitHash[:7])
	}

	// Restore
	exec.Command("git", "-C", targetDir, "checkout", "main").Run()
}