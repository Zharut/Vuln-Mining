import { BrowserRouter, Routes, Route } from "react-router-dom";
import Dashboard from "./Dashboard";
import ProjectDetail from "./ProjectDetail";

function App() {
    return (
        <BrowserRouter>
            <div className="min-h-screen bg-gray-950 text-gray-100 font-sans">
                <Routes>
                    <Route path="/" element={<Dashboard />} />
                    <Route path="/project/:id" element={<ProjectDetail />} />
                </Routes>
            </div>
        </BrowserRouter>
    );
}

export default App;