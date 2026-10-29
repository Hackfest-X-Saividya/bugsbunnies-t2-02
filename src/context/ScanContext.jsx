import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { findings, endpoints, demoProjectName } from "../data/mockData.js";
import {
  addLiveScan,
  readScanHistory,
  selectLiveScan,
  writeScanHistory,
} from "../services/scanHistory.js";

const ScanContext = createContext(null);
const INITIAL_REVIEW = { status: "Needs Review", isFlagged: false, flagReason: "" };
const initialDemoScan = {
  id: "demo-scan-01",
  projectName: demoProjectName,
  status: "Demo data",
  findings,
  endpoints,
  isDemo: true,
};

export function ScanProvider({ children }) {
  const [history, setHistory] = useState(() => readScanHistory());
  const [storageError, setStorageError] = useState(history.error);
  const [demoScan, setDemoScan] = useState(null);
  const [review, setReview] = useState({});
  const selectedLiveScan = history.scans.find((item) => item.id === history.selectedScanId);
  const scan = demoScan ?? selectedLiveScan ?? initialDemoScan;

  useEffect(() => {
    if (!history.scans.length) return;
    setStorageError(writeScanHistory(undefined, history));
  }, [history]);

  const setScan = useCallback((nextScan) => {
    setReview({});
    if (nextScan.isDemo === true) {
      setDemoScan(nextScan);
      return;
    }
    setDemoScan(null);
    setHistory((current) => addLiveScan(current, {
      ...nextScan,
      completedAt: nextScan.completedAt || new Date().toISOString(),
      isDemo: false,
    }));
  }, []);
  const selectScan = useCallback((scanId) => {
    if (!history.scans.some((item) => item.id === scanId)) return;
    setHistory((current) => selectLiveScan(current, scanId));
    setDemoScan(null);
    setReview({});
  }, [history.scans]);
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
    scan,
    scans: history.scans,
    selectedScanId: scan.isDemo ? null : history.selectedScanId,
    storageError,
    setScan,
    selectScan,
    getReview,
    updateReview,
    removeFlag,
  }), [scan, history, storageError, setScan, selectScan, getReview, updateReview, removeFlag]);
  return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>;
}

export function useScan() {
  const value = useContext(ScanContext);
  if (!value) throw new Error("useScan must be used within ScanProvider");
  return value;
}
