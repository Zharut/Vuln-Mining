import { useState, useEffect } from 'react'
import axios from 'axios'
import { Link } from 'react-router-dom'
import { ArrowLeft, Search, X, ExternalLink, ShieldAlert, Loader2, Clock } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, CartesianGrid, LabelList } from 'recharts'

function DeepAnalytics() {
    //State Manage
    const [languages, setLanguages] = useState([])
    const [selectedLang, setSelectedLang] = useState('')
    const [reportMode, setReportMode] = useState('frequent')
    const [data, setData] = useState([])
    const [loading, setLoading] = useState(false)
    const [sortOrder, setSortOrder] = useState('desc')

    //Modal
    const [modalOpen, setModalOpen] = useState(false)
    const [selectedVuln, setSelectedVuln] = useState(null)
    const [vulnDetails, setVulnDetails] = useState(null)
    const [loadingDetails, setLoadingDetails] = useState(false)

    // Load Languages
    useEffect(() => {
        axios.get('http://localhost:8081/api/options/languages')
            .then(res => {
                // 1. ''  เป็น 'Misc'
                const processedLangs = (res.data || []).map(l => (!l || l.trim() === '') ? 'Misc' : l);

                // null เป็น Misc
                const uniqueLangs = [...new Set(processedLangs)];

                setLanguages(uniqueLangs);
                if (uniqueLangs.length > 0) setSelectedLang(uniqueLangs[0]);
            })
    }, [])

    //Fetch Data
    useEffect(() => {
        if (!selectedLang) return
        setLoading(true)

        let url = `http://localhost:8081/api/report/vulnerabilities?lang=${selectedLang}&mode=${reportMode}`

        // 🔥 แก้ไขแล้ว: เพิ่มพารามิเตอร์ ?lang= ให้กับ API โหมด MTTR
        if (reportMode === 'mttr') {
            url = `http://localhost:8081/api/report/mttr?lang=${selectedLang}`
        }

        axios.get(url, { timeout: 30000 }) // 30 second timeout
            .then(res => {
                let resultData = res.data || []

                // แปลงข้อมูล MTTR ให้เข้ากับกราฟแท่งเดิม
                if (reportMode === 'mttr') {
                    resultData = resultData.filter(item => item.language === selectedLang || (selectedLang === 'Misc' && item.language === 'Misc'))
                    resultData = resultData.map(item => ({
                        // ดักชื่อตัวแปรครอบคลุมทุกแบบที่ API อาจจะส่งมา
                        name: item.vulnerability_id || item.name || item.vuln_id || item.id || 'Unknown Vuln',
                        count: parseFloat((item.avg_days_to_fix || 0).toFixed(1))
                    }))
                }

                setData(resultData)
                setLoading(false)
            })
            .catch(err => {
                console.error(`Error fetching ${reportMode} data:`, err)
                setData([]) // Clear data on error to prevent showing stale data
                setLoading(false)
            })
    }, [selectedLang, reportMode])

    //Sorting/Layout
    const sortedData = [...data].sort((a, b) => {
        if (sortOrder === 'desc') return b.count - a.count;
        return a.count - b.count;
    })

    // ความสูงกราฟ
    const chartHeight = Math.max(500, sortedData.length * 40);

    const handleVulnClick = async (vulnId) => {
        setSelectedVuln(vulnId)
        setModalOpen(true)
        setVulnDetails(null)
        setLoadingDetails(true)

        const checkLocalDB = async (id) => {
            try {
                const res = await axios.get(`http://localhost:8081/api/knowledge/${id}`)
                if (res.data && res.data.title) {
                    // แปลง References จาก String JSON เป็น Array
                    let refs = []
                    try { refs = JSON.parse(res.data.references_json) } catch (e) { }

                    return {
                        id: res.data.vulnerability_id,
                        summary: res.data.description,
                        published: "Internal Database",
                        cvss: res.data.cvss_score || "N/A",
                        references: [res.data.remediation, ...refs].filter(Boolean) // เอาวิธีแก้มาใส่รวมใน ref
                    }
                }
            } catch (e) {
                return null
            }
        }

        try {
            let details = {}

            if (vulnId.startsWith('CKV') || vulnId.startsWith('generic') || vulnId.startsWith('github') || vulnId.includes('SECRET')) {
                const localData = await checkLocalDB(vulnId)
                if (localData) {
                    details = localData
                } else {
                    throw new Error("Internal finding details missing in DB")
                }
            }
            else if (vulnId.startsWith('CVE-')) {
                try {
                    // 1. ลองหาเว็บนอกก่อน
                    const res = await axios.get(`http://localhost:8081/api/proxy/cve/${vulnId}`)
                    if (res.data && res.data.id && res.data.summary) {
                        details = {
                            id: res.data.id,
                            summary: res.data.summary,
                            published: res.data.Published,
                            cvss: res.data.cvss || 'N/A',
                            references: res.data.references || []
                        }
                    } else { throw new Error("External Empty") }
                } catch (extErr) {
                    // 2. ถ้าเว็บนอกล่ม -> มาหาใน DB
                    const localData = await checkLocalDB(vulnId)
                    if (localData) {
                        details = localData
                    } else {
                        // 3. ถ้าไม่มี ลอง OSV
                        const resBackup = await axios.get(`http://localhost:8081/api/proxy/ghsa/${vulnId}`)
                        if (resBackup.data && resBackup.data.id) {
                            let sevDisplay = 'Check Ref';
                            if (resBackup.data.severity && resBackup.data.severity.length > 0) {
                                sevDisplay = resBackup.data.severity[0].score || resBackup.data.severity[0].type;
                            }
                            details = {
                                id: resBackup.data.id,
                                summary: resBackup.data.summary || "No description.",
                                published: resBackup.data.published,
                                cvss: sevDisplay,
                                references: resBackup.data.references ? resBackup.data.references.map(r => r.url) : []
                            }
                        } else {
                            throw new Error("Not found anywhere")
                        }
                    }
                }
            }
            else if (vulnId.startsWith('GHSA-')) {
                const res = await axios.get(`http://localhost:8081/api/proxy/ghsa/${vulnId}`)
                if (res.data) {
                    let sevDisplay = 'Check GitHub';
                    if (res.data.severity && res.data.severity.length > 0) {
                        sevDisplay = res.data.severity[0].score || res.data.severity[0].type;
                    }
                    details = {
                        id: res.data.id,
                        summary: res.data.summary,
                        published: res.data.published,
                        cvss: sevDisplay,
                        references: res.data.references ? res.data.references.map(r => r.url) : []
                    }
                }
            }

            setVulnDetails(details)

        } catch (err) {
            let failMsg = "Details not found."
            if (vulnId.includes('2025') || vulnId.includes('2026')) {
                failMsg = `⚠️ Future/Simulated Vulnerability (${vulnId}).`
            } else if (vulnId.startsWith('CKV') || vulnId.includes('SECRET')) {
                failMsg = "Internal scanner finding. Please run SQL Insert to populate details manually."
            }
            setVulnDetails({ error: true, summary: failMsg })
        } finally {
            setLoadingDetails(false)
        }
    }

    const getBarColor = () => {
        if (reportMode === 'frequent') return '#EF4444'; // แดง
        if (reportMode === 'mttr') return '#F59E0B';     // ส้มเหลือง
        return '#10B981';                                // เขียว
    }

    return (
        <div className="p-8 max-w-7xl mx-auto min-h-screen bg-gray-950 text-gray-100 font-sans relative">

            {/* --- Header --- */}
            <Link to="/" className="text-gray-400 hover:text-white flex items-center gap-2 mb-8 transition-colors">
                <ArrowLeft size={20} /> Back to Dashboard
            </Link>
            <div className="mb-10">
                <h1 className="text-4xl font-bold text-white mb-2 flex items-center gap-3">
                    Full Spectrum Analysis
                </h1>
                <p className="text-gray-400 text-lg">
                    {reportMode === 'mttr' ? 'Analyzing Average Days to Remediate (MTTR)' : 'Click on bar to see real-time Summary.'}
                </p>
            </div>

            {/* --- Controls Bar --- */}
            <div className="bg-gray-900 p-6 rounded-2xl border border-gray-800 shadow-xl mb-8 flex flex-col xl:flex-row gap-6 items-start justify-between">
                {/* Language Selector */}
                <div className="w-full xl:w-1/4">
                    <label className="block text-xs text-gray-400 mb-2 font-bold uppercase tracking-wider">Language</label>
                    <div className="relative">
                        <Search className="absolute left-3 top-3 text-gray-500" size={18} />
                        <select
                            className="w-full bg-gray-950 border border-gray-700 text-white pl-10 pr-4 py-3 rounded-xl outline-none font-bold focus:ring-2 focus:ring-blue-500"
                            value={selectedLang}
                            onChange={e => setSelectedLang(e.target.value)}
                        >
                            {languages.map(l => <option key={l} value={l}>{l}</option>)}
                        </select>
                    </div>
                </div>

                {/* Mode Selector */}
                <div className="w-full xl:w-auto flex flex-col">
                    <label className="block text-xs text-gray-400 mb-2 font-bold uppercase tracking-wider">Analysis Mode</label>
                    <div className="flex bg-gray-950 p-1 rounded-xl border border-gray-800">
                        <button onClick={() => setReportMode('frequent')} className={`px-4 py-2 rounded-lg font-bold text-sm transition-all ${reportMode === 'frequent' ? 'bg-red-600 text-white' : 'text-gray-400 hover:text-white'}`}>Frequent</button>
                        <button onClick={() => setReportMode('fixed')} className={`px-4 py-2 rounded-lg font-bold text-sm transition-all ${reportMode === 'fixed' ? 'bg-green-600 text-white' : 'text-gray-400 hover:text-white'}`}>Fixed</button>
                        <button onClick={() => setReportMode('mttr')} className={`flex items-center gap-1 px-4 py-2 rounded-lg font-bold text-sm transition-all ${reportMode === 'mttr' ? 'bg-yellow-600 text-white' : 'text-gray-400 hover:text-white'}`}>
                            <Clock size={16} /> MTTR
                        </button>
                    </div>
                </div>

                {/* Sorting Selector */}
                <div className="w-full xl:w-auto flex flex-col">
                    <label className="block text-xs text-gray-400 mb-2 font-bold uppercase tracking-wider">Sorting</label>
                    <div className="flex bg-gray-950 p-1 rounded-xl border border-gray-800">
                        <button onClick={() => setSortOrder('desc')} className={`px-4 py-2 rounded-lg font-bold text-sm transition-all ${sortOrder === 'desc' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white'}`}>High → Low</button>
                        <button onClick={() => setSortOrder('asc')} className={`px-4 py-2 rounded-lg font-bold text-sm transition-all ${sortOrder === 'asc' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white'}`}>Low → High</button>
                    </div>
                </div>
            </div>

            {/* --- Chart Section --- */}
            <div className="bg-gray-900 rounded-2xl border border-gray-800 shadow-2xl overflow-hidden flex flex-col min-h-[500px]">
                {/* Header of Chart Box */}
                <div className="p-4 border-b border-gray-800 flex justify-between items-center bg-gray-900/50">
                    <span className="text-sm text-gray-400 font-mono">Found {sortedData.length} unique records</span>
                </div>

                {/* Conditional Rendering to avoid Recharts errors */}
                {sortedData.length > 0 ? (
                    <div className="w-full overflow-y-auto max-h-[800px] bg-gray-900 custom-scrollbar">
                        {/* Dynamic Height Container */}
                        <div style={{ height: `${chartHeight}px`, minHeight: '500px', width: '100%' }} className="p-4">
                            <ResponsiveContainer width="100%" height="100%">
                                <BarChart
                                    data={sortedData}
                                    layout="vertical"
                                    margin={{ top: 5, right: 30, left: 10, bottom: 5 }}
                                    onClick={(data) => {
                                        if (data && data.activePayload && data.activePayload[0]) {
                                            handleVulnClick(data.activePayload[0].payload.name);
                                        }
                                    }}
                                >
                                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" horizontal={true} vertical={true} />
                                    <XAxis type="number" stroke="#9CA3AF" position="top" />
                                    <YAxis
                                        dataKey="name"
                                        type="category"
                                        width={350}
                                        stroke="#E5E7EB"
                                        tick={{ fontSize: 12, fontWeight: '500', fill: '#E5E7EB', cursor: 'pointer' }}
                                        interval={0}
                                        onClick={(data) => handleVulnClick(data.value)}
                                    />
                                    <Tooltip
                                        cursor={{ fill: 'rgba(255,255,255,0.05)' }}
                                        contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151', color: '#fff' }}
                                        formatter={(value) => reportMode === 'mttr' ? [`${value} Days`, 'Avg Time to Fix'] : [value, 'Occurrences']}
                                    />
                                    <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={20} cursor="pointer">
                                        <LabelList
                                            dataKey="count"
                                            position="right"
                                            fill="#D1D5DB"
                                            fontSize={12}
                                            fontWeight="bold"
                                            formatter={(value) => reportMode === 'mttr' ? `${value} Days` : value}
                                        />
                                        {sortedData.map((entry, index) => (
                                            <Cell key={`cell-${index}`} fill={getBarColor()} />
                                        ))}
                                    </Bar>
                                </BarChart>
                            </ResponsiveContainer>
                        </div>
                    </div>
                ) : (
                    //empty
                    <div className="flex-1 flex flex-col items-center justify-center text-gray-500 min-h-[400px]">
                        {loading ? <Loader2 className="animate-spin mb-2" size={32} /> : <Search size={48} className="mb-4 opacity-20" />}
                        <p>{loading ? "Analyzing vast datasets..." : "No vulnerabilities found matching these criteria."}</p>
                    </div>
                )}
            </div>

            {/*Modal Popup*/}
            {modalOpen && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm transition-opacity" onClick={() => setModalOpen(false)}>
                    <div className="bg-gray-900 border border-gray-700 w-full max-w-2xl rounded-2xl shadow-2xl overflow-hidden transform transition-all scale-100" onClick={e => e.stopPropagation()}>

                        {/* Modal Header */}
                        <div className="bg-gray-800 p-4 flex justify-between items-center border-b border-gray-700">
                            <h3 className="text-xl font-bold text-white flex items-center gap-2">
                                <ShieldAlert className="text-red-500" /> {selectedVuln}
                            </h3>
                            <button onClick={() => setModalOpen(false)} className="text-gray-400 hover:text-white transition bg-gray-700/50 p-1 rounded-full">
                                <X size={20} />
                            </button>
                        </div>

                        {/* Modal Content */}
                        <div className="p-6 max-h-[70vh] overflow-y-auto">
                            {loadingDetails ? (
                                <div className="flex flex-col items-center justify-center py-10 text-blue-400">
                                    <Loader2 size={40} className="animate-spin mb-4" />
                                    <p className="animate-pulse">Establishing secure connection to intelligence DB...</p>
                                </div>
                            ) : vulnDetails && !vulnDetails.error ? (
                                <div className="space-y-6">
                                    {/* Success State */}
                                    <div className="flex items-center gap-4">
                                        <div className="bg-gray-800 p-3 rounded-lg text-center min-w-[100px]">
                                            <span className="text-xs font-bold text-gray-500 uppercase tracking-wider block">Severity</span>
                                            <span className="text-sm font-bold text-yellow-400 break-all">
                                                {vulnDetails.cvss}
                                            </span>
                                        </div>
                                        <div className="bg-gray-800 p-3 rounded-lg flex-1">
                                            <span className="text-xs font-bold text-gray-500 uppercase tracking-wider block">Published</span>
                                            <span className="text-lg font-medium text-gray-300">
                                                {vulnDetails.published ? new Date(vulnDetails.published).toLocaleDateString() : 'N/A'}
                                            </span>
                                        </div>
                                    </div>

                                    <div>
                                        <span className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-2 block">Summary</span>
                                        <div className="bg-gray-800/50 p-4 rounded-lg border border-gray-700/50">
                                            <p className="text-gray-200 leading-relaxed text-sm">{vulnDetails.summary}</p>
                                        </div>
                                    </div>

                                    {vulnDetails.references && vulnDetails.references.length > 0 && (
                                        <div>
                                            <span className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-2 block">Official References</span>
                                            <ul className="space-y-2">
                                                {vulnDetails.references.slice(0, 3).map((ref, i) => (
                                                    <li key={i}>
                                                        <a href={ref} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:text-blue-300 hover:underline flex items-center gap-2 text-sm truncate transition-colors">
                                                            <ExternalLink size={14} /> {ref}
                                                        </a>
                                                    </li>
                                                ))}
                                            </ul>
                                        </div>
                                    )}
                                </div>
                            ) : (
                                // Error/Not Found
                                <div className="text-center py-8">
                                    <div className="bg-red-500/10 text-red-400 p-4 rounded-xl border border-red-500/20 inline-block mb-4">
                                    </div>
                                    <h4 className="text-lg font-bold text-white mb-2">Intelligence Not Available</h4>
                                    <p className="text-gray-400 max-w-md mx-auto text-sm leading-relaxed">
                                        {vulnDetails?.summary || "No external details found."}
                                    </p>
                                </div>
                            )}
                        </div>

                        {/* Modal Footer */}
                        <div className="bg-gray-800 p-4 border-t border-gray-700 text-right flex justify-end">
                            <a href={`https://google.com/search?q=${selectedVuln}`} target="_blank" rel="noopener noreferrer"
                                className="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white px-5 py-2.5 rounded-lg font-bold text-sm transition shadow-lg shadow-blue-900/20">
                                Search on Google <ExternalLink size={16} />
                            </a>
                        </div>
                    </div>
                </div>
            )}
        </div>
    )
}

export default DeepAnalytics