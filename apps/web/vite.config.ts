import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { mockApiPlugin } from "./mock-api";

const mockApi = process.env.PICKET_MOCK_API === "1";

export default defineConfig({
  plugins: [react(), mockApiPlugin(mockApi)],
  server: {
    port: 5173,
    proxy: mockApi
      ? undefined
      : {
          "/api": "http://localhost:8787",
          "/health": "http://localhost:8787",
          "/device": "http://localhost:8787"
        }
  }
});
