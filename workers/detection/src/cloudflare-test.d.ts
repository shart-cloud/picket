import type { DetectionEnv } from "./index";

declare global {
  namespace Cloudflare {
    interface Env extends DetectionEnv {}
  }
}

export {};
