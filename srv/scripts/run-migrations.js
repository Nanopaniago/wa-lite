import { t as run } from "../chunks/migrations-Dh9z5yLA.js";
//#region src/scripts/run-migrations.js
var direction = process.argv[2] || "up";
run(direction).catch((err) => {
	console.error("Migration failed:", err);
	process.exit(1);
});
//#endregion
export {};

//# sourceMappingURL=run-migrations.js.map