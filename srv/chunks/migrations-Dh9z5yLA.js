import { t as configSchema } from "./load-config-D-6K5UFX.js";
import path from "node:path";
import { load } from "migrate";
//#region src/migrations.ts
var migrationsLoaders = /* #__PURE__ */ Object.assign({
	"../migrations/1694360000000-create-folders.ts": () => import("./1694360000000-create-folders-D1qI2Fzw.js"),
	"../migrations/1694360479680-create-account-db.js": () => import("./1694360479680-create-account-db-DHgFTBdL.js"),
	"../migrations/1694362247011-create-secret-table.js": () => import("./1694362247011-create-secret-table-CfYpVIrj.js"),
	"../migrations/1702667624000-rename-nordigen-secrets.js": () => import("./1702667624000-rename-nordigen-secrets-DZUTmd2i.js"),
	"../migrations/1718889148000-openid.js": () => import("./1718889148000-openid-BMYC_I3U.js"),
	"../migrations/1719409568000-multiuser.js": () => import("./1719409568000-multiuser-D4_e6ALu.js"),
	"../migrations/1763873568237-server-global-prefs.js": () => import("./1763873568237-server-global-prefs-yXZxPF-g.js"),
	"../migrations/1763873600000-backfill-files-owner.js": () => import("./1763873600000-backfill-files-owner-CRFzqqaJ.js"),
	"../migrations/1793059200000-create-api-keys.ts": () => import("./1793059200000-create-api-keys-C3qtzIT-.js"),
	"../migrations/1793232000000-user-passwords.js": () => import("./1793232000000-user-passwords-Db6daiXy.js")
});
async function loadMigrationModules(loaders) {
	const migrationsModules = {};
	for (const key of Object.keys(loaders).sort()) {
		const fileName = key.slice(key.lastIndexOf("/") + 1).replace(/\.ts$/, ".js");
		if (Object.prototype.hasOwnProperty.call(migrationsModules, fileName)) throw new Error(`Duplicate migration title: ${fileName}`);
		migrationsModules[fileName] = await loaders[key]();
	}
	return migrationsModules;
}
async function run(direction = "up") {
	console.log(`Checking if there are any migrations to run for direction "${direction}"...`);
	try {
		const migrationsModules = await loadMigrationModules(migrationsLoaders);
		return new Promise((resolve, reject) => {
			load({
				stateStore: `${path.join(configSchema.get("dataDir"), ".migrate")}${configSchema.get("mode") === "test" ? "-test" : ""}`,
				migrations: migrationsModules
			}, (err, set) => {
				if (err) return reject(err);
				set[direction]((err) => {
					if (err) return reject(err);
					console.log("Migrations: DONE");
					resolve();
				});
			});
		});
	} catch (err) {
		console.error("Error during migration process:", err);
		throw err;
	}
}
//#endregion
export { run as t };

//# sourceMappingURL=migrations-Dh9z5yLA.js.map