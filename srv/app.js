import { t as run } from "./chunks/migrations-Dh9z5yLA.js";
//#region app.ts
run().then(() => {
	return import("./chunks/app-CLHtiAzx.js").then((app) => app.run());
}).catch((err) => {
	console.log("Error starting app:", err);
	process.exit(1);
});
//#endregion
export {};

//# sourceMappingURL=app.js.map