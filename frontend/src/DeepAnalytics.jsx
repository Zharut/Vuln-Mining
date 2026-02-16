import { useState, useEffect } from 'react'
import axios from 'axios'
import { Link } from 'react-router-dom'
import { ArrowLeft, Trophy, Search, X, ExternalLink, ShieldAlert, Loader2 } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, CartesianGrid } from 'recharts'

function DeepAnalytics() {
    //State Manage
    const [languages, setLanguages] = useState([])
    const [selectedLang, setSelectedLang] = useState('')
    const [reportMode, setReportMode] = useState('frequent') // 'frequent' | 'fixed'
    const [data, setData] = useState([])
    const [loading, setLoading] = useState(false)
    const [sortOrder, setSortOrder] = useState('desc') // 'desc' | 'asc'

    //Modal
    const [modalOpen, setModalOpen] = useState(false)
    const [selectedVuln, setSelectedVuln] = useState(null)
    const [vulnDetails, setVulnDetails] = useState(null)
    const [loadingDetails, setLoadingDetails] = useState(false)

    //Load Languages on Mount
    useEffect(() => {
        axios.get('http://localhost:8081/api/options/languages')
            .then(res => {
                setLanguages(res.data || [])
                if (res.data.length > 0) setSelectedLang(res.data[0])
            })
    }, [])

    //Fetch Data
    useEffect(() => {
        if (!selectedLang) return
        setLoading(true)
        axios.get(`http://localhost:8081/api/report/vulnerabilities?lang=${selectedLang}&mode=${reportMode}`)
            .then(res => {
                setData(res.data || [])
                setLoading(false)
            })
            .catch(err => {
                console.error(err)
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

    //Click Handler-
    const handleVulnClick = async (vulnId) => {
        setSelectedVuln(vulnId)
        setModalOpen(true)
        setVulnDetails(null)
        setLoadingDetails(true)

        try {
            let details = {}

            // CASE A: CVE IDs
            if (vulnId.startsWith('CVE-')) {
                // Step 1: ลองดึงจาก cve.circl.lu
                try {
                    const res = await axios.get(`http://localhost:8081/api/proxy/cve/${vulnId}`)
                    if (res.data && res.data.id) {
                        details = {
                            id: res.data.id,
                            summary: res.data.summary || "No detailed description provided by source.",
                            published: res.data.Published,
                            cvss: res.data.cvss || 'N/A',
                            references: res.data.references || []
                        }
                    } else {
                        throw new Error("Empty data from primary source")
                    }
                } catch (primaryErr) {
                    // Step 2: Fallback ไปหาใน OSV ผ่าน Proxy GHSA
                    console.warn("Primary source failed, trying fallback...", primaryErr)
                    const resBackup = await axios.get(`http://localhost:8081/api/proxy/ghsa/${vulnId}`)

                    if (resBackup.data && resBackup.data.id) {
                        let sevDisplay = 'Check Ref';
                        if (resBackup.data.severity && resBackup.data.severity.length > 0) {
                            sevDisplay = resBackup.data.severity[0].score || resBackup.data.severity[0].type;
                        }

                        details = {
                            id: resBackup.data.id,
                            summary: resBackup.data.summary || resBackup.data.details,
                            published: resBackup.data.published,
                            cvss: sevDisplay,
                            references: resBackup.data.references ? resBackup.data.references.map(r => r.url) : []
                        }
                    } else {
                        throw new Error("Not found in any database")
                    }
                }
            }
            // CASE B: GHSA IDs
            else if (vulnId.startsWith('GHSA-')) {
                const res = await axios.get(`http://localhost:8081/api/proxy/ghsa/${vulnId}`)
                if (res.data) {
                    let sevDisplay = 'Check GitHub';
                    if (res.data.severity && res.data.severity.length > 0) {
                        sevDisplay = res.data.severity[0].score || res.data.severity[0].type;
                    }

                    details = {
                        id: res.data.id,
                        summary: res.data.summary || res.data.details || "No description available.",
                        published: res.data.published,
                        cvss: sevDisplay,
                        references: res.data.references ? res.data.references.map(r => r.url) : []
                    }
                }
            }
            // CASE C: Internal Findings
            else {
                throw new Error("Internal/Private Finding")
            }

            setVulnDetails(details)

        } catch (err) {
            console.warn("Lookup finalized with error:", err)

            let failMsg = "Details not found in public databases."

            // เช็คว่าเป็น CVE ของปีอนาคตไหท
            if (vulnId.includes('2025') || vulnId.includes('2026')) {
                failMsg = `This ID (${vulnId}) corresponds to a simulated or future vulnerability timeframe (System Year: 2026). Public databases (NVD/MITRE) do not have records for this yet.`
            } else if (!vulnId.startsWith('CVE') && !vulnId.startsWith('GHSA')) {
                failMsg = "This appears to be an internal scanner finding (e.g., Secret Key, Misconfiguration), not a public CVE."
            }

            setVulnDetails({
                error: true,
                summary: failMsg
            })
        } finally {
            setLoadingDetails(false)
        }
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
                <p className="text-gray-400 text-lg">Click on any bar to see real-time intelligence.</p>
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
                                        width={220}
                                        stroke="#E5E7EB"
                                        tick={{ fontSize: 12, fontWeight: '500', cursor: 'pointer' }}
                                        interval={0}
                                        onClick={(data) => handleVulnClick(data.value)}
                                    />
                                    <Tooltip cursor={{ fill: 'rgba(255,255,255,0.05)' }} contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151', color: '#fff' }} />
                                    <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={20} cursor="pointer">
                                        {sortedData.map((entry, index) => (
                                            <Cell key={`cell-${index}`} fill={reportMode === 'frequent' ? '#EF4444' : '#10B981'} />
                                        ))}
                                    </Bar>
                                </BarChart>
                            </ResponsiveContainer>
                        </div>
                    </div>
                ) : (
                    // Empty State
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
                                            {/* ตรงนี้จะแสดง Score หรือ Vector string */}
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
                                        <ShieldAlert size={48} className="mx-auto" />
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