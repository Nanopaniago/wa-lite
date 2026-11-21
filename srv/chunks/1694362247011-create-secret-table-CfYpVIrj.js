import { i as getAccountDb } from "./account-db-DNaHpKvL.js";
//#region migrations/1694362247011-create-secret-table.js
var up = async function() {
	await getAccountDb().exec(`
    CREATE TABLE IF NOT EXISTS secrets (
      name TEXT PRIMARY KEY,
      value BLOB
    );
  `);
};
var down = async function() {
	await getAccountDb().exec(`
    DROP TABLE secrets;
  `);
};
//#endregion
export { down, up };

//# sourceMappingURL=1694362247011-create-secret-table-CfYpVIrj.js.map