import { useState, useEffect } from 'react'
import axios from 'axios'
import { Link } from 'react-router-dom' // <-- สำคัญ! ต้องมีบรรทัดนี้
import { ShieldAlert, BarChart3, Filter, Layers, Database, Microscope } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, CartesianGrid } from 'recharts'

function Dashboard() {
    // State สำหรับเก็บข้อมูล
    const [data, setData] = useState([])

    // State สำหรับการควบคุม (Control)
    const [groupBy, setGroupBy] = useState('vulnerability_id')
    const [selectedSeverities, setSelectedSeverities] = useState(['CRITICAL', 'HIGH', 'MEDIUM'])
    const [minStars, setMinStars] = useState(0)

    // สีสำหรับกราฟ
    const COLORS = ['#3B82F6', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6', '#EC4899'];

    useEffect(() => {
        fetchAnalytics()
    }, [groupBy, selectedSeverities, minStars])

    const fetchAnalytics = async () => {
        try {
            const params = new URLSearchParams()
            params.append('group_by', groupBy)
            params.append('min_stars', minStars)
            selectedSeverities.forEach(s => params.append('severity', s))

            const res = await axios.get(`http://localhost:8081/api/analytics?${params.toString()}`)
            setData(res.data || [])
        } catch (err) { console.error(err) }
    }

    const toggleSeverity = (sev) => {
        setSelectedSeverities(prev =>
            prev.includes(sev) ? prev.filter(s => s !== sev) : [...prev, sev]
        )
    }

    return (
        <div className="p-8 max-w-7xl mx-auto min-h-screen bg-gray-950 text-gray-100">

            <header className="mb-8 border-b border-gray-800 pb-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                <div>
                    <h1 className="text-3xl font-bold text-green-500 flex items-center gap-2">
                        Vulnerability Analytics
                    </h1>
                </div>

                {/* ปุ่มไปหน้า Deep Analysis */}
                <Link to="/deep-dive" className="bg-purple-600 hover:bg-purple-500 text-white px-4 py-2 rounded-lg font-bold flex items-center gap-2 transition shadow-lg shadow-purple-900/20">
                    Deep Analysis
                </Link>
            </header>

            {/* --- 🎛️ CONTROL PANEL --- */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">

                {/* 1. Group By Setting */}
                <div className="bg-gray-900 p-5 rounded-xl border border-gray-800">
                    <h3 className="text-blue-400 font-bold mb-3 flex items-center gap-2">
                        Group By
                    </h3>
                    <select
                        className="w-full bg-gray-950 border border-gray-700 p-3 rounded text-white focus:border-blue-500 outline-none"
                        value={groupBy}
                        onChange={(e) => setGroupBy(e.target.value)}
                    >
                        <option value="vulnerability_id">Type of Vulnerability</option>
                        <option value="language">Programming Language</option>
                        <option value="severity">Severity Level</option>
                        <option value="tool">Scanner Tool</option>
                    </select>
                </div>

                {/* 2. Severity Filter */}
                <div className="bg-gray-900 p-5 rounded-xl border border-gray-800">
                    <h3 className="text-red-400 font-bold mb-3 flex items-center gap-2">
                        Severity Filter
                    </h3>
                    <div className="grid grid-cols-2 gap-2">
                        {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].map(sev => (
                            <label key={sev} className="flex items-center gap-2 cursor-pointer hover:bg-gray-800 p-1 rounded">
                                <input
                                    type="checkbox"
                                    checked={selectedSeverities.includes(sev)}
                                    onChange={() => toggleSeverity(sev)}
                                    className="w-4 h-4 accent-green-500"
                                />
                                <span className={`text-sm font-mono ${selectedSeverities.includes(sev) ? 'text-white' : 'text-gray-500'}`}>
                                    {sev}
                                </span>
                            </label>
                        ))}
                    </div>
                </div>

                {/* 3. Star Filter */}
                <div className="bg-gray-900 p-5 rounded-xl border border-gray-800">
                    <h3 className="text-yellow-400 font-bold mb-3 flex items-center gap-2">
                        Project Quality
                    </h3>
                    <div className="space-y-2">
                        <label className="text-sm text-gray-400">Minimum Stars:</label>
                        <input
                            type="number"
                            value={minStars}
                            onChange={(e) => setMinStars(e.target.value)}
                            className="w-full bg-gray-950 border border-gray-700 p-2 rounded text-white"
                        />
                    </div>
                </div>
            </div>

            {/*RESULT*/}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">

                {/* Graph */}
                <div className="lg:col-span-2 bg-gray-900 p-6 rounded-xl border border-gray-800 shadow-xl min-h-[400px]">
                    <h3 className="text-white font-bold mb-6 flex items-center gap-2">
                        Visual Distribution
                    </h3>
                    <div className="h-[350px] w-full">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={data} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                                <XAxis dataKey="name" stroke="#9CA3AF" tick={{ fontSize: 12 }} />
                                <YAxis stroke="#9CA3AF" />
                                <Tooltip contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151', color: '#fff' }} />
                                <Bar dataKey="value" fill="#3B82F6" radius={[4, 4, 0, 0]}>
                                    {data.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                    ))}
                                </Bar>
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                {/* Table */}
                <div className="bg-gray-900 p-6 rounded-xl border border-gray-800 shadow-xl overflow-hidden flex flex-col">
                    <h3 className="text-white font-bold mb-4 flex items-center gap-2">
                        Detailed Counts
                    </h3>
                    <div className="overflow-y-auto flex-1 pr-2 max-h-[400px]">
                        <table className="w-full text-left">
                            <thead className="bg-gray-950 text-gray-400 text-xs uppercase sticky top-0">
                                <tr>
                                    <th className="p-3">Group Name</th>
                                    <th className="p-3 text-right">Count</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-800">
                                {data.map((item, idx) => (
                                    <tr key={idx} className="hover:bg-gray-800 transition">
                                        <td className="p-3 text-gray-300 font-mono text-sm truncate max-w-[150px]" title={item.name}>
                                            {item.name || 'Unknown'}
                                        </td>
                                        <td className="p-3 text-right font-bold text-white">
                                            {item.value.toLocaleString()}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>

            </div>
        </div>
    )
}

export default Dashboard