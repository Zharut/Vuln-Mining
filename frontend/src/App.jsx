import { BrowserRouter, Routes, Route } from "react-router-dom";
import Dashboard from "./Dashboard";
import ProjectDetail from "./ProjectDetail";
import DeepAnalytics from "./DeepAnalytics"; // <-- 1. Import ไฟล์ใหม่

function App() {
    return (
        <BrowserRouter>
            <div className="min-h-screen bg-gray-950 text-gray-100 font-sans">
                <Routes>
                    <Route path="/" element={<Dashboard />} />
                    <Route path="/project/:id" element={<ProjectDetail />} />
                    <Route path="/deep-dive" element={<DeepAnalytics />} /> {/* <-- 2. เพิ่ม Route */}
                </Routes>
            </div>
        </BrowserRouter>
    );
}

export default App;