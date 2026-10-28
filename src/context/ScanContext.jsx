import { createContext, useContext, useMemo, useState } from "react";
import { findings, endpoints, demoProjectName } from "../data/mockData.js";

const ScanContext = createContext(null);

export function ScanProvider({ children }) {
  const [scan, setScan] = useState({
    id: "demo-scan-01",
    projectName: demoProjectName,
    status: "Demo data",
    findings,
    endpoints,
    isDemo: true,
  });
  const value = useMemo(() => ({ scan, setScan }), [scan]);
  return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>;
}

export function useScan() {
  const value = useContext(ScanContext);
  if (!value) throw new Error("useScan must be used within ScanProvider");
  return value;
}
