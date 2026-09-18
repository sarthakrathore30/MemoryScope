import { createContext, useCallback, useContext, useState } from "react";
import { casesApi } from "../api/client";

const CasesContext = createContext(null);

export function CasesProvider({ children }) {
  const [cases, setCases] = useState([]);

  const refresh = useCallback(async () => {
    const data = await casesApi.list();
    setCases(data);
    return data;
  }, []);

  return (
    <CasesContext.Provider value={{ cases, refresh }}>
      {children}
    </CasesContext.Provider>
  );
}

export function useCases() {
  const ctx = useContext(CasesContext);
  if (!ctx) throw new Error("useCases must be used within a CasesProvider");
  return ctx;
}
