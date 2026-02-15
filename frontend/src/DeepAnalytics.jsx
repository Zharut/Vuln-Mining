import { useState, useEffect } from 'react'
import axios from 'axios'
import { Link } from 'react-router-dom'
import { ArrowLeft, Trophy, Bug, CheckCircle2, Search } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, CartesianGrid } from 'recharts'

function DeepAnalytics() {
    // State
    const [languages, setLanguages] = useState([])
    const [selectedLang, setSelectedLang] = useState('')
    const [reportMode, setReportMode] = useState('frequent') // frequent | fixed
    const [data, setData] = useState([])
    const [loading, setLoading] = useState(false)

    // Load Languages on Start
    useEffect(() => {
        axios.get('http://localhost:8081/api/options/languages')
            .then(res => {
                setLanguages(res.data || [])
                if (res.data.length > 0) setSelectedLang(res.data[0]) // เลือกภาษาแรกให้อัตโนมัติ
            })
    }, [])

    // Load Data when Filter Changes
    useEffect(() => {
        if (!selectedLang) return
        setLoading(true)
        axios.get(`http://localhost:8081/api/report/vulnerabilities?lang=${selectedLang}&mode=${reportMode}`)
            .then(res => {
                setData(res.data || [])
                setLoading(false)
            })
            .catch(err => setLoading(false))
    }, [selectedLang, reportMode])

    const COLORS = ['#3B82F6', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6'];

    return (
        <div className="p-8 max-w-6xl mx-auto min-h-screen bg-gray-950 text-gray-100 font-sans">

            {/* Header */}
            <Link to="/" className="text-gray-400 hover:text-white flex items-center gap-2 mb-8 transition-colors">
                <ArrowLeft size={20} /> Back to Dashboard
            </Link>
            <div className="mb-10">
                <h1 className="text-4xl font-bold text-white mb-2 flex items-center gap-3">
                    <Trophy className="text-yellow-500" size={40} />
                    Language Health Report
                </h1>
                <p className="text-gray-400 text-lg">Analyze vulnerability trends per programming language.</p>
            </div>

            {/* --- 🎛️ CONTROLS --- */}
            <div className="bg-gray-900 p-6 rounded-2xl border border-gray-800 shadow-xl mb-8 flex flex-col md:flex-row gap-6 items-center justify-between">

                {/* 1. Language Selector */}
                <div className="w-full md:w-1/3">
                    <label className="block text-sm text-gray-400 mb-2 font-bold uppercase tracking-wider">
                        Select Language
                    </label>
                    <div className="relative">
                        <Search className="absolute left-3 top-3 text-gray-500" size={18} />
                        <select
                            className="w-full bg-gray-950 border border-gray-700 text-white pl-10 pr-4 py-3 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none appearance-none font-medium text-lg"
                            value={selectedLang}
                            onChange={e => setSelectedLang(e.target.value)}
                        >
                            {languages.map(l => <option key={l} value={l}>{l}</option>)}
                        </select>
                    </div>
                </div>

                {/* 2. Mode Toggle (Tab Style) */}
                <div className="flex bg-gray-950 p-1 rounded-xl border border-gray-800">
                    <button
                        onClick={() => setReportMode('frequent')}
                        className={`flex items-center gap-2 px-6 py-3 rounded-lg font-bold transition-all ${reportMode === 'frequent'
                                ? 'bg-red-500 text-white shadow-lg shadow-red-500/30'
                                : 'text-gray-400 hover:text-white'
                            }`}
                    >
                        <Bug size={20} /> Most Frequent Issues
                    </button>
                    <button
                        onClick={() => setReportMode('fixed')}
                        className={`flex items-center gap-2 px-6 py-3 rounded-lg font-bold transition-all ${reportMode === 'fixed'
                                ? 'bg-green-500 text-white shadow-lg shadow-green-500/30'
                                : 'text-gray-400 hover:text-white'
                            }`}
                    >
                        <CheckCircle2 size={20} /> Most Fixed Issues
                    </button>
                </div>
            </div>

            {/* --- 📊 CHART SECTION --- */}
            <div className="bg-gray-900 p-8 rounded-2xl border border-gray-800 shadow-2xl min-h-[500px]">
                <h2 className="text-2xl font-bold mb-6 flex items-center gap-3">
                    <span className="text-blue-400">Top 10:</span>
                    {reportMode === 'frequent' ? `Most Common Vulnerabilities in ${selectedLang}` : `Issues Often Fixed in ${selectedLang}`}
                </h2>

                {loading ? (
                    <div className="h-[400px] flex items-center justify-center text-gray-500 animate-pulse">
                        Calculating deep analytics...
                    </div>
                ) : data.length > 0 ? (
                    <div className="h-[400px] w-full">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart
                                data={data}
                                layout="vertical"
                                margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
                            >
                                <CartesianGrid strokeDasharray="3 3" stroke="#374151" horizontal={false} />
                                <XAxis type="number" stroke="#9CA3AF" />
                                <YAxis
                                    dataKey="name"
                                    type="category"
                                    width={200}
                                    stroke="#E5E7EB"
                                    tick={{ fontSize: 14, fontWeight: 'bold' }}
                                />
                                <Tooltip
                                    contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151', borderRadius: '8px' }}
                                    cursor={{ fill: '#1F2937' }}
                                />
                                <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={20}>
                                    {data.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={reportMode === 'frequent' ? '#EF4444' : '#10B981'} />
                                    ))}
                                </Bar>
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                ) : (
                    <div className="h-[400px] flex flex-col items-center justify-center text-gray-500">
                        <Search size={48} className="mb-4 opacity-20" />
                        <p>No data found for this criteria.</p>
                    </div>
                )}
            </div>

            {/* คำอธิบายด้านล่าง */}
            <div className="mt-6 text-center text-gray-500 text-sm">
                {reportMode === 'frequent'
                    ? "This chart shows which vulnerabilities appear most often across all project snapshots."
                    : "This chart counts vulnerabilities that existed in the past but are NOT present in the latest snapshot (Fixed)."}
            </div>
        </div>
    )
}

export default DeepAnalytics