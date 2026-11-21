import { t as configSchema } from "../chunks/load-config-D-6K5UFX.js";
import { fetch } from "undici";
//#region src/scripts/health-check.ts
var protocol = configSchema.get("https.key") && configSchema.get("https.cert") ? "https" : "http";
var hostname = configSchema.get("hostname") === "::" ? "localhost" : configSchema.get("hostname");
function getHealthStatus(response) {
	if (typeof response === "object" && response !== null && "status" in response && typeof response.status === "string") return response.status;
}
fetch(`${protocol}://${hostname}:${configSchema.get("port")}/health`).then((response) => response.json()).then((response) => {
	const status = getHealthStatus(response);
	if (status !== "UP") throw new Error("Health check failed: Server responded to health check with status " + status);
}).catch((err) => {
	console.log("Health check failed:", err);
	process.exit(1);
});
//#endregion
export {};

//# sourceMappingURL=health-check.js.map