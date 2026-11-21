import { i as getAccountDb } from "./account-db-DNaHpKvL.js";
//#region migrations/1793232000000-user-passwords.js
var up = async function() {
	getAccountDb().exec("ALTER TABLE users ADD COLUMN password_hash TEXT;");
};
var down = async function() {
	getAccountDb().exec("ALTER TABLE users DROP COLUMN password_hash;");
};
//#endregion
export { down, up };

//# sourceMappingURL=1793232000000-user-passwords-Db6daiXy.js.map