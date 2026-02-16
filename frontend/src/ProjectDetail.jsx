import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import axios from 'axios'
import { ArrowLeft, CheckCircle, XCircle, AlertTriangle, Terminal } from 'lucide-react'

function ProjectDetail() {
    const { id } = useParams()
    const [project, setProject] = useState(null)
    const [loading, setLoading] = useState(true)
    const [selectedCommit, setSelectedCommit] = useState(null)

    useEffect(() => {
        axios.get(`http://localhost:8081/api/project/${id}`)
            .then(res => {
                setProject(res.data)
                // เลือก Commit ล่าสุดเป็นค่าเริ่มต้น
                if (res.data.Commits && res.data.Commits.length > 0) {
                    // เรียงลำดับตามเวลา
                    const sorted = res.data.Commits.sort((a, b) => new Date(b.committed_at) - new Date(a.committed_at))
                    setSelectedCommit(sorted[0])
                }
                setLoading(false)
            })
            .catch(err => console.error(err))
    }, [id])

    if (loading) return <div className="p-10 text-center text-green-500">Loading details...</div>
    if (!project) return <div className="p-10 text-center text-red-500">Project not found</div>

    // รวม Findings ของ Commit ที่เลือก
    const currentFindings = selectedCommit?.Scans?.flatMap(s => s.Findings || []) || []

    return (
        <div className="p-8 max-w-7xl mx-auto">
            <Link to="/" className="text-gray-400 hover:text-white flex items-center gap-2 mb-6">
                <ArrowLeft size={20} /> Back to Dashboard
            </Link>

            {/* Project Header */}
            <div className="flex justify-between items-start mb-8">
                <div>
                    <h1 className="text-3xl font-bold text-white mb-2">{project.owner} / {project.repo_name}</h1>
                    <div className="flex gap-4 text-sm text-gray-400">
                        <span className="bg-gray-800 px-2 py-1 rounded">⭐ {project.stars} Stars</span>
                        <span className="bg-gray-800 px-2 py-1 rounded">🔤 {project.language || 'Unknown'}</span>
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">

                {/* LEFT: Timeline of Commits */}
                <div className="lg:col-span-1 bg-gray-900 border border-gray-800 rounded-xl p-4 h-[600px] overflow-y-auto">
                    <h3 className="text-gray-400 uppercase text-xs font-bold mb-4">Commit History</h3>
                    <div className="space-y-3">
                        {project.Commits?.sort((a, b) => new Date(b.committed_at) - new Date(a.committed_at)).map(commit => {
                            // นับจำนวนช่องโหว่รวมใน Commit นี้
                            const totalVulns = commit.Scans?.reduce((acc, scan) => acc + (scan.Findings ? scan.Findings.length : 0), 0) || 0
                            const isSelected = selectedCommit?.commit_id === commit.commit_id

                            return (
                                <div key={commit.commit_id}
                                    onClick={() => setSelectedCommit(commit)}
                                    className={`p-3 rounded-lg cursor-pointer border transition ${isSelected ? 'bg-gray-800 border-blue-500' : 'bg-gray-950 border-gray-800 hover:border-gray-600'
                                        }`}>
                                    <div className="flex justify-between items-center mb-1">
                                        <span className="font-mono text-xs text-blue-400">{commit.commit_hash.substring(0, 7)}</span>
                                        <span className="text-xs text-gray-500">{new Date(commit.committed_at).toLocaleDateString()}</span>
                                    </div>
                                    <div className="text-sm text-gray-300 truncate mb-2">{commit.message}</div>

                                    {/* Status Badge */}
                                    <div className="flex items-center gap-2 text-xs">
                                        {totalVulns === 0 ? (
                                            <span className="flex items-center gap-1 text-green-400 bg-green-900/20 px-2 py-0.5 rounded">
                                                <CheckCircle size={12} /> Fixed / Clean
                                            </span>
                                        ) : (
                                            <span className="flex items-center gap-1 text-red-400 bg-red-900/20 px-2 py-0.5 rounded">
                                                <XCircle size={12} /> {totalVulns} Issues
                                            </span>
                                        )}
                                    </div>
                                </div>
                            )
                        })}
                    </div>
                </div>

                {/* RIGHT: Vulnerability Details */}
                <div className="lg:col-span-2 bg-gray-900 border border-gray-800 rounded-xl p-6 h-[600px] overflow-y-auto">
                    <h3 className="text-gray-400 uppercase text-xs font-bold mb-4 flex items-center gap-2">
                        <Terminal size={16} />
                        Scan Results for Commit: <span className="text-white font-mono">{selectedCommit?.commit_hash.substring(0, 7)}</span>
                    </h3>

                    {currentFindings.length === 0 ? (
                        <div className="flex flex-col items-center justify-center h-full text-green-500">
                            <CheckCircle size={64} className="mb-4 opacity-50" />
                            <h2 className="text-2xl font-bold">No Vulnerabilities Found!</h2>
                            <p className="text-gray-400">This snapshot is clean or issues have been fixed.</p>
                        </div>
                    ) : (
                        <div className="space-y-4">
                            {currentFindings.map(f => (
                                <div key={f.finding_id} className="bg-gray-950 border border-red-900/30 rounded-lg p-4 hover:border-red-500/50 transition">
                                    <div className="flex justify-between items-start mb-2">
                                        <h4 className="font-bold text-red-400 flex items-center gap-2">
                                            <AlertTriangle size={18} /> {f.vulnerability_id}
                                        </h4>
                                        <span className="bg-gray-800 text-xs px-2 py-1 rounded uppercase">{f.tool}</span>
                                    </div>
                                    <p className="text-gray-300 text-sm mb-3">{f.message}</p>
                                    <div className="bg-gray-900 p-2 rounded text-xs font-mono text-gray-400 border border-gray-800">
                                        📄 File: <span className="text-white">{f.file_path}</span>
                                        <span className="mx-2">|</span>
                                        🔢 Line: <span className="text-white">{f.line_number}</span>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>

            </div>
        </div>
    )
}

export default ProjectDetail