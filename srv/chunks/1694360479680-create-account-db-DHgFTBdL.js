import { i as getAccountDb } from "./account-db-DNaHpKvL.js";
//#region migrations/1694360479680-create-account-db.js
var up = async function() {
	await getAccountDb().exec(`
    CREATE TABLE IF NOT EXISTS auth
      (password TEXT PRIMARY KEY);

    CREATE TABLE IF NOT EXISTS sessions
      (token TEXT PRIMARY KEY);

    CREATE TABLE IF NOT EXISTS files
      (id TEXT PRIMARY KEY,
       group_id TEXT,
       sync_version SMALLINT,
       encrypt_meta TEXT,
       encrypt_keyid TEXT,
       encrypt_salt TEXT,
       encrypt_test TEXT,
       deleted BOOLEAN DEFAULT FALSE,
       name TEXT);
  `);
};
var down = async function() {
	await getAccountDb().exec(`
    DROP TABLE auth;
    DROP TABLE sessions;
    DROP TABLE files;
  `);
};
//#endregion
export { down, up };

//# sourceMappingURL=1694360479680-create-account-db-DHgFTBdL.js.map