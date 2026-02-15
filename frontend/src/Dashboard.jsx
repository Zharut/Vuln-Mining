import { useState, useEffect } from 'react'
import axios from 'axios'
import { Link } from 'react-router-dom'
import { Search, ShieldAlert, GitBranch, Star, Filter } from 'lucide-react'

function Dashboard() {
    const [projects, setProjects] = useState([])
    const [stats, setStats] = useState({ total_projects: 0, total_vulns: 0 })
    const [filters, setFilters] = useState({
        name: '',
        lang: '',
        minStars: 0,
        maxStars: 1000000
    })

    useEffect(() => {
        fetchData()
    }, []) // Load ครั้งแรก

    // ฟังก์ชันดึงข้อมูลพร้อมส่ง Query Params ไปให้ Backend
    const fetchData = async () => {
        try {
            const query = new URLSearchParams({
                lang: filters.lang,
                min_stars: filters.minStars,
                max_stars: filters.maxStars
            }).toString()

            const projRes = await axios.get(`http://localhost:8081/api/projects?${query}`)
            const statRes = await axios.get('http://localhost:8081/api/stats')
            setProjects(projRes.data || [])
            setStats(statRes.data || {})
        } catch (err) { console.error(err) }
    }

    // Filter ชื่อในเครื่อง (Client-side)
    const filteredProjects = projects.filter(p =>
        (p.repo_name || "").toLowerCase().includes(filters.name.toLowerCase()) ||
        (p.owner || "").toLowerCase().includes(filters.name.toLowerCase())
    )

    return (
        <div className="p-8 max-w-7xl mx-auto">
            {/* Header & Stats */}
            <header className="mb-8 flex justify-between items-center border-b border-gray-800 pb-6">
                <div>
                    <h1 className="text-3xl font-bold text-green-500 flex items-center gap-2">
                        <ShieldAlert /> Vuln Mining Center
                    </h1>
                    <p className="text-gray-500">Monitor & Analyze Vulnerabilities</p>
                </div>
                <div className="flex gap-4">
                    <div className="bg-gray-900 p-4 rounded border border-gray-800">
                        <div className="text-xs text-gray-400">PROJECTS</div>
                        <div className="text-2xl font-bold">{stats.total_projects}</div>
                    </div>
                    <div className="bg-gray-900 p-4 rounded border border-red-900/30">
                        <div className="text-xs text-gray-400">VULNERABILITIES</div>
                        <div className="text-2xl font-bold text-red-500">{stats.total_vulns}</div>
                    </div>
                </div>
            </header>

            {/* Advanced Filters */}
            <div className="bg-gray-900 p-6 rounded-xl border border-gray-800 mb-8">
                <div className="flex items-center gap-2 mb-4 text-blue-400 font-semibold">
                    <Filter size={20} /> Advanced Filters
                </div>
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <input
                        type="text" placeholder="Search Name..."
                        className="bg-gray-950 border border-gray-700 p-2 rounded text-white"
                        value={filters.name} onChange={e => setFilters({ ...filters, name: e.target.value })}
                    />
                    <input
                        type="text" placeholder="Language (e.g. Go)"
                        className="bg-gray-950 border border-gray-700 p-2 rounded text-white"
                        value={filters.lang} onChange={e => setFilters({ ...filters, lang: e.target.value })}
                    />
                    <div className="flex gap-2">
                        <input
                            type="number" placeholder="Min Stars"
                            className="bg-gray-950 border border-gray-700 p-2 rounded text-white w-full"
                            onChange={e => setFilters({ ...filters, minStars: e.target.value })}
                        />
                        <input
                            type="number" placeholder="Max Stars"
                            className="bg-gray-950 border border-gray-700 p-2 rounded text-white w-full"
                            onChange={e => setFilters({ ...filters, maxStars: e.target.value })}
                        />
                    </div>
                    <button
                        onClick={fetchData}
                        className="bg-green-600 hover:bg-green-500 text-white p-2 rounded font-bold transition">
                        Apply Filters
                    </button>
                </div>
            </div>

            {/* Table */}
            <div className="bg-gray-900 rounded-xl overflow-hidden border border-gray-800">
                <table className="w-full text-left">
                    <thead className="bg-gray-950 text-gray-400 uppercase text-xs">
                        <tr>
                            <th className="p-4">Project</th>
                            <th className="p-4">Lang</th>
                            <th className="p-4">Stars</th>
                            <th className="p-4">Snapshots</th>
                            <th className="p-4">Action</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800">
                        {filteredProjects.map(p => (
                            <tr key={p.project_id} className="hover:bg-gray-800 transition">
                                <td className="p-4">
                                    <div className="text-lg font-medium text-blue-400">
                                        {p.owner} / <span className="font-bold">{p.repo_name}</span>
                                    </div>
                                </td>
                                <td className="p-4 text-gray-400">{p.language || '-'}</td>
                                <td className="p-4 text-yellow-500 flex items-center gap-1">
                                    <Star size={14} /> {(p.stars || 0).toLocaleString()}
                                </td>
                                <td className="p-4">
                                    <div className="flex items-center gap-2">
                                        <GitBranch size={16} className="text-purple-400" />
                                        {p.Commits ? p.Commits.length : 0}
                                    </div>
                                </td>
                                <td className="p-4">
                                    <Link to={`/project/${p.project_id}`}
                                        className="bg-blue-600 hover:bg-blue-500 text-white px-3 py-1 rounded text-sm">
                                        View Analysis
                                    </Link>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    )
}

export default Dashboard