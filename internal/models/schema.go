package models

import (
	"time"
)

type Project struct {
	ProjectID  string    `gorm:"primaryKey;column:project_id" json:"project_id"`
	RepoURL    string    `gorm:"column:repo_url" json:"repo_url"`
	Owner      string    `gorm:"column:owner" json:"owner"`         // <-- แก้ให้ React อ่านเจอ
	RepoName   string    `gorm:"column:repo_name" json:"repo_name"` // <-- แก้ให้ React อ่านเจอ
	Language  string    `gorm:"column:language" json:"language"`
	Stars      float64   `gorm:"column:stars" json:"stars"`
	Status     string    `gorm:"column:status;default:active" json:"status"`
	PCreatedAt time.Time `gorm:"column:p_created_at" json:"p_created_at"`
	UpdatedAt  time.Time `gorm:"column:updated_at" json:"updated_at"`

	//1 Project มีหลาย Commits
	Commits []Commit `gorm:"foreignKey:ProjectID" json:"Commits"`
}

type Commit struct {
	CommitID    string    `gorm:"primaryKey;column:commit_id" json:"commit_id"`
	ProjectID   string    `gorm:"column:project_id" json:"project_id"`
	CommitHash  string    `gorm:"column:commit_hash;unique" json:"commit_hash"`
	Branch      string    `gorm:"column:branch" json:"branch"`
	Message     string    `gorm:"column:message" json:"message"`
	AuthorName  string    `gorm:"column:author_name" json:"author_name"`
	CommittedAt time.Time `gorm:"column:committed_at" json:"committed_at"`
	CCreatedAt  time.Time `gorm:"column:c_created_at;autoCreateTime" json:"c_created_at"`

	//Commitมี Scan อะไรบ้าง
	Scans []Scan `gorm:"foreignKey:CommitID" json:"Scans"`
}

type Scan struct {
	ScanID     string    `gorm:"primaryKey;column:scan_id" json:"scan_id"`
	CommitID   string    `gorm:"column:commit_id" json:"commit_id"`
	ToolUsed   string    `gorm:"column:tool_used" json:"tool_used"`
	ScanStatus string    `gorm:"column:scan_status" json:"scan_status"`
	StartedAt  time.Time `gorm:"column:started_at" json:"started_at"`
	FinishedAt time.Time `gorm:"column:finished_at" json:"finished_at"`
	LogOutput  string    `gorm:"column:log_output" json:"log_output"`

	//หา Findings
	Findings []Finding `gorm:"foreignKey:ScanID" json:"Findings"`
}

type Finding struct {
	FindingID       string    `gorm:"primaryKey;column:finding_id" json:"finding_id"`
	ScanID          string    `gorm:"column:scan_id" json:"scan_id"`
	VulnerabilityID string    `gorm:"column:vulnerability_id" json:"vulnerability_id"`
	Tool            string    `gorm:"column:tool" json:"tool"`
	CweID           string    `gorm:"column:cwe_id" json:"cwe_id"`
	Severity        string    `gorm:"column:severity" json:"severity"`
	FilePath        string    `gorm:"column:file_path" json:"file_path"`
	LineNumber      int       `gorm:"column:line_number" json:"line_number"`
	Message         string    `gorm:"column:message" json:"message"`
	Fingerprint     string    `gorm:"column:fingerprint" json:"fingerprint"`
	Status          string    `gorm:"column:status" json:"status"`
	FCreatedAt      time.Time `gorm:"column:f_created_at" json:"f_created_at"`
}

type VulnerabilityDetail struct {
	VulnerabilityID string  `gorm:"primaryKey;column:vulnerability_id" json:"vulnerability_id"`
	Title           string  `gorm:"column:title" json:"title"`
	Description     string  `gorm:"column:description" json:"description"`
	Remediation     string  `gorm:"column:remediation" json:"remediation"`
	CvssScore       float64 `gorm:"column:cvss_score" json:"cvss_score"`
	ReferencesJSON  string  `gorm:"column:references_json" json:"references_json"`
}

func (Finding) TableName() string { return "findings" }
func (Project) TableName() string { return "projects" }
func (Commit) TableName() string { return "commits" }
func (Scan) TableName()   string { return "scans" }
func (VulnerabilityDetail) TableName() string { return "vulnerability_details" }