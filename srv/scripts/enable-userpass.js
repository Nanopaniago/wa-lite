import { x as setupMasterUser } from "../chunks/account-db-DNaHpKvL.js";
//#region src/scripts/enable-userpass.js
var username = process.env.NFINANCE_USER;
var password = process.env.NFINANCE_PASSWORD;
var displayName = process.env.NFINANCE_NAME;
if (!username || !password) {
	console.log("Defina NFINANCE_USER e NFINANCE_PASSWORD.");
	process.exit(1);
}
var { error } = await setupMasterUser({
	username,
	password,
	displayName
});
if (error) {
	console.log("Erro:", error);
	process.exit(2);
}
console.log(`Conta master "${username}" criada. Login por utilizador ativo.`);
//#endregion
export {};

//# sourceMappingURL=enable-userpass.js.map