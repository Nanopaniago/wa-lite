import { i as getAccountDb } from "./account-db-DNaHpKvL.js";
//#region migrations/1702667624000-rename-nordigen-secrets.js
var up = async function() {
	await getAccountDb().exec(`UPDATE secrets SET name = 'gocardless_secretId' WHERE name = 'nordigen_secretId'`);
	await getAccountDb().exec(`UPDATE secrets SET name = 'gocardless_secretKey' WHERE name = 'nordigen_secretKey'`);
};
var down = async function() {
	await getAccountDb().exec(`UPDATE secrets SET name = 'nordigen_secretId' WHERE name = 'gocardless_secretId'`);
	await getAccountDb().exec(`UPDATE secrets SET name = 'nordigen_secretKey' WHERE name = 'gocardless_secretKey'`);
};
//#endregion
export { down, up };

//# sourceMappingURL=1702667624000-rename-nordigen-secrets-DZUTmd2i.js.map