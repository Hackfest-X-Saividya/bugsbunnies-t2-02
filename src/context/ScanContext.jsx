import { createContext, useCallback, useContext, useMemo, useState } from "react";
import { findings, endpoints, demoProjectName } from "../data/mockData.js";

const ScanContext = createContext(null);
const INITIAL_REVIEW = { status: "Needs Review", isFlagged: false, flagReason: "" };

export function ScanProvider({ children }) {
  const [scan, setScanState] = useState({
    id: "demo-scan-01",
    projectName: demoProjectName,
    status: "Demo data",
    findings,
    endpoints,
    isDemo: true,
  });
  const [review, setReview] = useState({});
  const setScan = useCallback((nextScan) => {
    setScanState(nextScan);
    setReview({});
  }, []);
  const getReview = useCallback((findingId) => review[findingId] || INITIAL_REVIEW, [review]);
  const updateReview = useCallback((findingId, status, flagReason = "") => {
    setReview((current) => {
      const previous = current[findingId] || INITIAL_REVIEW;
      return {
        ...current,
        [findingId]: {
          ...previous,
          status,
          isFlagged: status === "Flagged for Removal" ? true : previous.isFlagged,
          flagReason: status === "Flagged for Removal" ? flagReason || previous.flagReason : previous.flagReason,
        },
      };
    });
  }, []);
  const removeFlag = useCallback((findingId) => {
    setReview((current) => {
      const previous = current[findingId] || INITIAL_REVIEW;
      return {
        ...current,
        [findingId]: {
          ...previous,
          status: previous.status === "Flagged for Removal" ? "Needs Review" : previous.status,
          isFlagged: false,
        },
      };
    });
  }, []);
  const value = useMemo(() => ({
    scan, setScan, getReview, updateReview, removeFlag,
  }), [scan, setScan, getReview, updateReview, removeFlag]);
  return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>;
}

export function useScan() {
  const value = useContext(ScanContext);
  if (!value) throw new Error("useScan must be used within ScanProvider");
  return value;
}
