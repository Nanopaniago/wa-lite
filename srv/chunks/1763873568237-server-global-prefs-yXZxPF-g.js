import { i as getAccountDb } from "./account-db-DNaHpKvL.js";
//#region migrations/1763873568237-server-global-prefs.js
var up = async function() {
	getAccountDb().exec(`
    CREATE TABLE IF NOT EXISTS server_prefs
      (key TEXT NOT NULL PRIMARY KEY,
       value TEXT);
  `);
};
var down = async function() {
	getAccountDb().exec(`
    DROP TABLE IF EXISTS server_prefs;
  `);
};
//#endregion
export { down, up };

//# sourceMappingURL=1763873568237-server-global-prefs-yXZxPF-g.js.map