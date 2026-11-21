import { t as configSchema } from "./load-config-D-6K5UFX.js";
import fs from "node:fs/promises";
//#region migrations/1694360000000-create-folders.ts
async function ensureExists(path) {
	try {
		await fs.mkdir(path);
	} catch (err) {
		if (err instanceof Error && "code" in err && err.code === "EEXIST") return null;
		throw err;
	}
}
var up = async function() {
	await ensureExists(configSchema.get("serverFiles"));
	await ensureExists(configSchema.get("userFiles"));
};
var down = async function() {
	await fs.rm(configSchema.get("serverFiles"), {
		recursive: true,
		force: true
	});
	await fs.rm(configSchema.get("userFiles"), {
		recursive: true,
		force: true
	});
};
//#endregion
export { down, up };

//# sourceMappingURL=1694360000000-create-folders-D1qI2Fzw.js.map