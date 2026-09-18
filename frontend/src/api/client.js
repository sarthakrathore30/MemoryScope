import axios from "axios";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api";

const client = axios.create({
  baseURL: API_BASE_URL,
});

export const casesApi = {
  list: () => client.get("/cases").then((r) => r.data),
  create: (caseName) => client.post("/cases", { case_name: caseName }).then((r) => r.data),
  get: (caseId) => client.get(`/cases/${caseId}`).then((r) => r.data),
  rename: (caseId, caseName) =>
    client.patch(`/cases/${caseId}`, { case_name: caseName }).then((r) => r.data),
  delete: (caseId) => client.delete(`/cases/${caseId}`),
  upload: (caseId, file, onProgress) => {
    const formData = new FormData();
    formData.append("file", file);
    return client
      .post(`/cases/${caseId}/upload`, formData, {
        headers: { "Content-Type": "multipart/form-data" },
        onUploadProgress: (evt) => {
          if (onProgress && evt.total) {
            onProgress(Math.round((evt.loaded * 100) / evt.total));
          }
        },
      })
      .then((r) => r.data);
  },
  analyze: (caseId) => client.post(`/cases/${caseId}/analyze`).then((r) => r.data),
  results: (caseId) => client.get(`/cases/${caseId}/results`).then((r) => r.data),
  auditLog: (caseId) => client.get(`/cases/${caseId}/audit-log`).then((r) => r.data),
  auditChainVerify: (caseId) => client.get(`/cases/${caseId}/audit-log/verify`).then((r) => r.data),
  reportUrl: (caseId, format) => `${API_BASE_URL}/cases/${caseId}/report?format=${format}`,
};

export function extractErrorMessage(error) {
  return error?.response?.data?.detail || error?.message || "An unexpected error occurred.";
}

export default client;
