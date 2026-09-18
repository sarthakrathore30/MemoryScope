import { useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, useNavigate } from "react-router-dom";
import CaseDocket from "./components/CaseDocket";
import CaseDetailPage from "./pages/CaseDetailPage";
import DashboardPage from "./pages/DashboardPage";
import { casesApi } from "./api/client";
import { CasesProvider, useCases } from "./context/CasesContext";
import { ToastProvider } from "./context/ToastContext";

function Shell() {
  const { cases, refresh } = useCases();
  const [creating, setCreating] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function handleCreateCase(name) {
    setCreating(true);
    try {
      const newCase = await casesApi.create(name);
      await refresh();
      navigate(`/cases/${newCase.case_id}`);
    } finally {
      setCreating(false);
    }
  }

  return (
    <div style={{ display: "flex" }}>
      <CaseDocket cases={cases} onCreateCase={handleCreateCase} creating={creating} />
      <Routes>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/cases/:caseId" element={<CaseDetailPage />} />
      </Routes>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <ToastProvider>
        <CasesProvider>
          <Shell />
        </CasesProvider>
      </ToastProvider>
    </BrowserRouter>
  );
}
