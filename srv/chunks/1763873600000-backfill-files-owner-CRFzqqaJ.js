import { i as getAccountDb } from "./account-db-DNaHpKvL.js";
//#region migrations/1763873600000-backfill-files-owner.js
var up = async function() {
	const accountDb = getAccountDb();
	const admin = accountDb.first("SELECT id FROM users WHERE role = ? ORDER BY id LIMIT 1", ["ADMIN"]);
	if (admin) accountDb.mutate("UPDATE files SET owner = ? WHERE owner IS NULL", [admin.id]);
};
var down = async function() {};
//#endregion
export { down, up };

//# sourceMappingURL=1763873600000-backfill-files-owner-CRFzqqaJ.js.map