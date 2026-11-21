import { t as configSchema } from "./load-config-D-6K5UFX.js";
import { join, resolve } from "node:path";
import createDebug from "debug";
import ipaddr from "ipaddr.js";
import { Issuer, custom, generators } from "openid-client";
import { v4 } from "uuid";
import * as argon2 from "argon2";
import * as bcrypt from "bcrypt";
import Database from "better-sqlite3";
//#region src/services/user-service.ts
function getUserByUsername(userName) {
	if (!userName || typeof userName !== "string") return null;
	const { id } = getAccountDb().first("SELECT id FROM users WHERE user_name = ?", [userName]) || {};
	return id || null;
}
function getUserById(userId) {
	if (!userId) return null;
	const { id } = getAccountDb().first("SELECT * FROM users WHERE id = ?", [userId]) || {};
	return id || null;
}
function getFileById(fileId) {
	if (!fileId) return null;
	const { id } = getAccountDb().first("SELECT * FROM files WHERE files.id = ?", [fileId]) || {};
	return id || null;
}
function validateRole(roleId) {
	return ["BASIC", "ADMIN"].some((a) => a === roleId);
}
function getOwnerCount() {
	const { ownerCount } = getAccountDb().first(`SELECT count(*) as ownerCount FROM users WHERE users.user_name <> '' and users.owner = 1`) || { ownerCount: 0 };
	return ownerCount;
}
function getOwnerId() {
	const { id } = getAccountDb().first(`SELECT users.id FROM users WHERE users.user_name <> '' and users.owner = 1`) || {};
	return id;
}
function getAllUsers() {
	return getAccountDb().all(`SELECT users.id, user_name as userName, display_name as displayName, enabled, ifnull(owner,0) as owner, role
     FROM users
     WHERE users.user_name <> ''`);
}
function insertUser(userId, userName, displayName, enabled, role, passwordHash = null) {
	getAccountDb().mutate("INSERT INTO users (id, user_name, display_name, enabled, owner, role, password_hash) VALUES (?, ?, ?, ?, 0, ?, ?)", [
		userId,
		userName,
		displayName,
		enabled,
		role,
		passwordHash
	]);
}
function updateUserWithRole(userId, userName, displayName, enabled, roleId) {
	getAccountDb().transaction(() => {
		getAccountDb().mutate("UPDATE users SET user_name = ?, display_name = ?, enabled = ?, role = ? WHERE id = ?", [
			userName,
			displayName,
			enabled,
			roleId,
			userId
		]);
		if (!enabled) getAccountDb().mutate("DELETE FROM sessions WHERE user_id = ?", [userId]);
	});
}
function deleteUser(userId) {
	return getAccountDb().transaction(() => {
		const { changes } = getAccountDb().mutate("DELETE FROM users WHERE id = ? and owner = 0", [userId]);
		if (changes > 0) getAccountDb().mutate("DELETE FROM sessions WHERE user_id = ?", [userId]);
		return changes;
	});
}
function deleteUserAccess(userId) {
	try {
		return getAccountDb().mutate("DELETE FROM user_access WHERE user_id = ?", [userId]).changes;
	} catch (error) {
		throw new Error(`Failed to delete user access: ${error.message}`);
	}
}
function transferAllFilesFromUser(ownerId, oldUserId) {
	if (!ownerId || !oldUserId) throw new Error("Invalid user IDs");
	try {
		getAccountDb().transaction(() => {
			if (!getUserById(ownerId)) throw new Error("New owner not found");
			getAccountDb().mutate("UPDATE files set owner = ? WHERE owner = ?", [ownerId, oldUserId]);
		});
	} catch (error) {
		throw new Error(`Failed to transfer files: ${error.message}`);
	}
}
function updateFileOwner(ownerId, fileId) {
	if (!ownerId || !fileId) throw new Error("Invalid parameters");
	try {
		if (getAccountDb().mutate("UPDATE files set owner = ? WHERE id = ?", [ownerId, fileId]).changes === 0) throw new Error("File not found");
	} catch (error) {
		throw new Error(`Failed to update file owner: ${error.message}`);
	}
}
function getUserAccess(fileId, userId, isAdmin) {
	return getAccountDb().all(`SELECT users.id as userId, user_name as userName, files.owner, display_name as displayName
     FROM users
     JOIN user_access ON user_access.user_id = users.id
     JOIN files ON files.id = user_access.file_id
     WHERE files.id = ? and (files.owner = ? OR 1 = ?)`, [
		fileId,
		userId,
		isAdmin ? 1 : 0
	]);
}
function canAccessActiveFile(fileId, userId) {
	return !!getAccountDb().first("SELECT id FROM files WHERE id = ? AND deleted = 0", [fileId]) && (isAdmin(userId) || countUserAccess(fileId, userId) > 0);
}
function countUserAccess(fileId, userId) {
	const { accessCount } = getAccountDb().first(`SELECT COUNT(*) as accessCount
       FROM files
       WHERE files.id = ? AND (files.owner = ? OR EXISTS (
         SELECT 1 FROM user_access
         WHERE user_access.user_id = ? AND user_access.file_id = ?)
       )`, [
		fileId,
		userId,
		userId,
		fileId
	]) || {};
	return accessCount || 0;
}
function checkFilePermission(fileId, userId) {
	return getAccountDb().first(`SELECT 1 as granted
       FROM files
       WHERE files.id = ? and (files.owner = ?)`, [fileId, userId]) || { granted: 0 };
}
function addUserAccess(userId, fileId) {
	if (!userId || !fileId) throw new Error("Invalid parameters");
	try {
		const userExists = getUserById(userId);
		const fileExists = getFileById(fileId);
		if (!userExists || !fileExists) throw new Error("User or file not found");
		getAccountDb().mutate("INSERT INTO user_access (user_id, file_id) VALUES (?, ?)", [userId, fileId]);
	} catch (error) {
		if (error.message.includes("UNIQUE constraint")) throw new Error("Access already exists");
		throw new Error(`Failed to add user access: ${error.message}`);
	}
}
function deleteUserAccessByFileId(userIds, fileId) {
	if (!Array.isArray(userIds) || userIds.length === 0) throw new Error("The provided userIds must be a non-empty array.");
	const CHUNK_SIZE = 999;
	let totalChanges = 0;
	try {
		getAccountDb().transaction(() => {
			for (let i = 0; i < userIds.length; i += CHUNK_SIZE) {
				const chunk = userIds.slice(i, i + CHUNK_SIZE);
				const sql = `DELETE FROM user_access WHERE user_id IN (${chunk.map(() => "?").join(",")}) AND file_id = ?`;
				const result = getAccountDb().mutate(sql, [...chunk, fileId]);
				totalChanges += result.changes;
			}
		});
	} catch (error) {
		throw new Error(`Failed to delete user access: ${error.message}`);
	}
	return totalChanges;
}
function getAllUserAccess(fileId) {
	const joinType = "LEFT JOIN";
	return getAccountDb().all(`
      SELECT
        users.id as userId,
        user_name     as userName,
        display_name  as displayName,
        CASE WHEN user_access.file_id IS NULL THEN 0 ELSE 1 END as haveAccess,
        CASE WHEN files.id IS NULL THEN 0 ELSE 1 END as owner
      FROM users
      ${joinType} user_access ON user_access.file_id = ? AND user_access.user_id = users.id
      ${joinType} files       ON files.id = ? AND files.owner = users.id
      WHERE users.enabled = 1
        AND users.user_name <> ''
    `, [fileId, fileId]);
}
function getOpenIDConfig() {
	return getAccountDb().first(`SELECT * FROM auth WHERE method = ?`, ["openid"]) || null;
}
var MS_PER_SECOND = 1e3;
function validateSession(req, res) {
	let { token } = req.body || {};
	if (!token) token = req.headers["x-actual-token"];
	const session = getSession(token);
	if (!session) {
		res.status(401);
		res.send({
			status: "error",
			reason: "unauthorized",
			details: "token-not-found"
		});
		return null;
	}
	if (session.expires_at !== -1 && session.expires_at * MS_PER_SECOND <= Date.now()) {
		res.status(401);
		res.send({
			status: "error",
			reason: "token-expired"
		});
		return null;
	}
	return session;
}
function validateAuthHeader(req) {
	const trustedAuthProxies = configSchema.get("trustedAuthProxies") ?? configSchema.get("trustedProxies");
	const peer = req.socket.remoteAddress;
	if (peer === void 0) {
		console.error(`Header Auth Login attempted but there was no defined peer.`);
		return false;
	}
	const peerIp = ipaddr.process(peer);
	const rangeList = { allowed_ips: trustedAuthProxies.map((q) => ipaddr.parseCIDR(q)) };
	if (ipaddr.subnetMatch(peerIp, rangeList, "fail") === "allowed_ips") {
		console.info(`Header Auth Login permitted from ${peer}`);
		return true;
	} else {
		console.warn(`Header Auth Login attempted from ${peer}`);
		return false;
	}
}
//#endregion
//#region src/accounts/password.js
var ARGON2_OPTIONS = {
	type: argon2.argon2id,
	memoryCost: 47104,
	timeCost: 1,
	parallelism: 1
};
function isValidPassword(password) {
	return typeof password === "string" && password.length > 0;
}
function hashPassword(password) {
	if (!isValidPassword(password)) throw new TypeError("invalid-password");
	return argon2.hash(password, ARGON2_OPTIONS);
}
async function verifyPassword(password, hash) {
	if (!isValidPassword(password) || typeof hash !== "string") return false;
	if (hash.startsWith("$argon2")) try {
		return await argon2.verify(hash, password);
	} catch {
		return false;
	}
	try {
		return await bcrypt.compare(password, hash);
	} catch {
		return false;
	}
}
function isLegacyHash(hash) {
	return typeof hash === "string" && !hash.startsWith("$argon2");
}
function setPasswordHash(hashed) {
	const accountDb = getAccountDb();
	accountDb.transaction(() => {
		accountDb.mutate("DELETE FROM auth WHERE method = ?", ["password"]);
		accountDb.mutate("UPDATE auth SET active = 0");
		accountDb.mutate("INSERT INTO auth (method, display_name, extra_data, active) VALUES ('password', 'Password', ?, 1)", [hashed]);
	});
}
async function bootstrapPassword(password) {
	if (!isValidPassword(password)) return { error: "invalid-password" };
	setPasswordHash(await hashPassword(password));
	return {};
}
async function loginWithPassword(password) {
	if (!isValidPassword(password)) return { error: "invalid-password" };
	const accountDb = getAccountDb();
	const { extra_data: passwordHash } = accountDb.first("SELECT extra_data FROM auth WHERE method = ?", ["password"]) || {};
	if (!passwordHash) return { error: "invalid-password" };
	if (!await verifyPassword(password, passwordHash)) return { error: "invalid-password" };
	const rehashed = isLegacyHash(passwordHash) ? await hashPassword(password) : null;
	return accountDb.transaction(() => {
		if (accountDb.first("SELECT extra_data FROM auth WHERE method = 'password'")?.extra_data !== passwordHash) return { error: "invalid-password" };
		if (rehashed) accountDb.mutate("UPDATE auth SET extra_data = ? WHERE method = 'password'", [rehashed]);
		const { totalOfUsers } = accountDb.first("SELECT count(*) as totalOfUsers FROM users");
		let userId = null;
		if (totalOfUsers === 0) {
			userId = v4();
			accountDb.mutate("INSERT INTO users (id, user_name, display_name, enabled, owner, role) VALUES (?, ?, ?, 1, 1, ?)", [
				userId,
				"",
				"",
				"ADMIN"
			]);
		} else {
			const { id: userIdFromDb } = accountDb.first("SELECT id FROM users WHERE user_name = ?", [""]);
			userId = userIdFromDb;
			if (!userId) return { error: "user-not-found" };
		}
		let expiration = -1;
		if (configSchema.get("token_expiration") !== "never" && configSchema.get("token_expiration") !== "openid-provider" && typeof configSchema.get("token_expiration") === "number") expiration = Math.floor(Date.now() / 1e3) + configSchema.get("token_expiration") * 60;
		const token = v4();
		accountDb.mutate("INSERT INTO sessions (token, expires_at, user_id, auth_method) VALUES (?, ?, ?, ?)", [
			token,
			expiration,
			userId,
			"password"
		]);
		clearExpiredSessions();
		return { token };
	});
}
async function changePassword(newPassword, currentPassword) {
	const accountDb = getAccountDb();
	if (!isValidPassword(newPassword)) return { error: "invalid-password" };
	const auth = accountDb.first("SELECT extra_data FROM auth WHERE method = 'password'");
	if (!auth) return { error: "no-password-method" };
	if (currentPassword !== void 0 && !await verifyPassword(currentPassword, auth.extra_data)) return { error: "invalid-current-password" };
	const hashed = await hashPassword(newPassword);
	return accountDb.transaction(() => {
		if (currentPassword !== void 0 && accountDb.first("SELECT extra_data FROM auth WHERE method = 'password'")?.extra_data !== auth.extra_data) return { error: "invalid-current-password" };
		if (accountDb.mutate("UPDATE auth SET extra_data = ? WHERE method = 'password'", [hashed]).changes === 0) return { error: "no-password-method" };
		accountDb.mutate("DELETE FROM sessions WHERE auth_method = 'password'");
		accountDb.mutate("DELETE FROM api_keys WHERE user_id IN (SELECT id FROM users WHERE user_name = '')");
		return {};
	});
}
async function checkPassword(password) {
	if (!isValidPassword(password)) return false;
	const { extra_data: passwordHash } = getAccountDb().first("SELECT extra_data FROM auth WHERE method = ?", ["password"]) || {};
	if (!passwordHash) return false;
	return await verifyPassword(password, passwordHash);
}
//#endregion
//#region src/accounts/openid.ts
var debugSensitive = createDebug("actual-sensitive:openid");
async function bootstrapOpenId(configParameter) {
	if (!("issuer" in configParameter) && !("discoveryURL" in configParameter)) return { error: "missing-issuer-or-discoveryURL" };
	if (!("client_id" in configParameter)) return { error: "missing-client-id" };
	if (!("client_secret" in configParameter)) return { error: "missing-client-secret" };
	if (!("server_hostname" in configParameter)) return { error: "missing-server-hostname" };
	custom.setHttpOptionsDefaults({ timeout: 2e4 });
	try {
		if (configParameter.discoveryURL) {
			configParameter.issuer = configParameter.discoveryURL;
			delete configParameter.discoveryURL;
		}
		await setupOpenIdClient(configParameter);
	} catch (error) {
		console.error("Error setting up OpenID client");
		debugSensitive("Error setting up OpenID client: %O", error);
		return { error: "configuration-error" };
	}
	const accountDb = getAccountDb();
	try {
		accountDb.transaction(() => {
			accountDb.mutate("DELETE FROM auth WHERE method = ?", ["openid"]);
			accountDb.mutate("UPDATE auth SET active = 0");
			accountDb.mutate("INSERT INTO auth (method, display_name, extra_data, active) VALUES ('openid', 'OpenID', ?, 1)", [JSON.stringify(configParameter)]);
		});
	} catch (error) {
		console.error("Error updating auth table");
		debugSensitive("Error updating auth table: %O", error);
		return { error: "database-error" };
	}
	return {};
}
async function setupOpenIdClient(configParameter) {
	return new (typeof configParameter.issuer === "string" ? await Issuer.discover(configParameter.issuer) : new Issuer({
		issuer: configParameter.issuer.name,
		authorization_endpoint: configParameter.issuer.authorization_endpoint,
		token_endpoint: configParameter.issuer.token_endpoint,
		userinfo_endpoint: configParameter.issuer.userinfo_endpoint
	})).Client({
		client_id: configParameter.client_id,
		client_secret: configParameter.client_secret,
		redirect_uri: new URL("/openid/callback", configParameter.server_hostname).toString(),
		validate_id_token: true
	});
}
async function loginWithOpenIdSetup(returnUrl, firstTimeLoginPassword = "") {
	if (!returnUrl) return { error: "return-url-missing" };
	if (!isValidRedirectUrl(returnUrl)) return { error: "invalid-return-url" };
	const accountDb = getAccountDb();
	const { countUsersWithUserName } = accountDb.first("SELECT count(*) as countUsersWithUserName FROM users WHERE user_name <> ?", [""]);
	if (countUsersWithUserName === 0) {
		if (listLoginMethods().some((authMethod) => authMethod.method === "password")) {
			if (!await checkPassword(firstTimeLoginPassword)) return { error: "invalid-password" };
		}
	}
	let config = accountDb.first("SELECT extra_data FROM auth WHERE method = ?", ["openid"]);
	if (!config) return { error: "openid-not-configured" };
	try {
		config = JSON.parse(config["extra_data"]);
	} catch (error) {
		console.error("Error parsing OpenID configuration");
		debugSensitive("Error parsing OpenID configuration: %O", error);
		return { error: "openid-setup-failed" };
	}
	let client;
	try {
		client = await setupOpenIdClient(config);
	} catch (error) {
		console.error("Error setting up OpenID client");
		debugSensitive("Error setting up OpenID client: %O", error);
		return { error: "openid-setup-failed" };
	}
	const state = generators.state();
	const code_verifier = generators.codeVerifier();
	const code_challenge = generators.codeChallenge(code_verifier);
	const now_time = Date.now();
	const expiry_time = now_time + 3e5;
	accountDb.mutate("DELETE FROM pending_openid_requests WHERE expiry_time < ?", [now_time]);
	accountDb.mutate("INSERT INTO pending_openid_requests (state, code_verifier, return_url, expiry_time) VALUES (?, ?, ?, ?)", [
		state,
		code_verifier,
		returnUrl,
		expiry_time
	]);
	return { url: client.authorizationUrl({
		response_type: "code",
		scope: "openid email profile",
		state,
		code_challenge,
		code_challenge_method: "S256"
	}) };
}
async function loginWithOpenIdFinalize(body) {
	if (!body.code) return { error: "missing-authorization-code" };
	if (!body.state) return { error: "missing-state" };
	const accountDb = getAccountDb();
	let configFromDb = accountDb.first("SELECT extra_data FROM auth WHERE method = 'openid' AND active = 1");
	if (!configFromDb) return { error: "openid-not-configured" };
	try {
		configFromDb = JSON.parse(configFromDb["extra_data"]);
	} catch (error) {
		console.error("Error parsing OpenID configuration");
		debugSensitive("Error parsing OpenID configuration: %O", error);
		return { error: "openid-setup-failed" };
	}
	let client;
	try {
		client = await setupOpenIdClient(configFromDb);
	} catch (error) {
		console.error("Error setting up OpenID client");
		debugSensitive("Error setting up OpenID client: %O", error);
		return { error: "openid-setup-failed" };
	}
	const pendingRequest = accountDb.first("SELECT code_verifier, return_url FROM pending_openid_requests WHERE state = ? AND expiry_time > ?", [body.state, Date.now()]);
	if (!pendingRequest) return { error: "invalid-or-expired-state" };
	const { code_verifier, return_url } = pendingRequest;
	try {
		let tokenSet = null;
		if (!configFromDb.authMethod || configFromDb.authMethod === "openid") {
			const params = {
				code: body.code,
				state: body.state,
				iss: body.iss
			};
			tokenSet = await client.callback(client.redirect_uris[0], params, {
				code_verifier,
				state: body.state
			});
		} else tokenSet = await client.grant({
			grant_type: "authorization_code",
			code: body.code,
			redirect_uri: client.redirect_uris[0],
			code_verifier
		});
		const userInfo = await client.userinfo(tokenSet.access_token);
		const identity = userInfo.preferred_username ?? userInfo.login ?? userInfo.email ?? userInfo.id ?? userInfo.sub;
		if (identity == null) return { error: "openid-grant-failed: no identification was found" };
		let userId = null;
		try {
			accountDb.transaction(() => {
				const { countUsersWithUserName } = accountDb.first("SELECT count(*) as countUsersWithUserName FROM users WHERE user_name <> ?", [""]);
				if (!accountDb.first("SELECT id FROM users WHERE user_name = ?", [identity]) && (countUsersWithUserName === 0 || configSchema.get("userCreationMode") === "login")) {
					userId = v4();
					accountDb.mutate("INSERT INTO users (id, user_name, display_name, enabled, owner, role) VALUES (?, ?, ?, 1, ?, ?)", [
						userId,
						identity,
						userInfo.name ?? userInfo.email ?? identity,
						countUsersWithUserName === 0 ? "1" : "0",
						countUsersWithUserName === 0 ? "ADMIN" : "BASIC"
					]);
					if (countUsersWithUserName === 0) {
						const userFromPasswordMethod = getUserByUsername("");
						if (userFromPasswordMethod) transferAllFilesFromUser(userId, userFromPasswordMethod.user_id);
					}
				} else {
					const { id: userIdFromDb, display_name: displayName } = accountDb.first("SELECT id, display_name FROM users WHERE user_name = ? and enabled = 1", [identity]) || {};
					if (userIdFromDb == null) throw new Error("openid-grant-failed");
					if (!displayName && userInfo.name) accountDb.mutate("UPDATE users set display_name = ? WHERE id = ?", [userInfo.name, userIdFromDb]);
					userId = userIdFromDb;
				}
			});
		} catch (error) {
			if (error.message === "user-already-exists") return { error: "user-already-exists" };
			else if (error.message === "openid-grant-failed") return { error: "openid-grant-failed" };
			else throw error;
		}
		const token = v4();
		let expiration;
		if (configSchema.get("token_expiration") === "openid-provider") expiration = tokenSet.expires_at ?? -1;
		else if (configSchema.get("token_expiration") === "never") expiration = -1;
		else if (typeof configSchema.get("token_expiration") === "number") expiration = Math.floor(Date.now() / 1e3) + configSchema.get("token_expiration");
		else expiration = Math.floor(Date.now() / 1e3) + 600;
		accountDb.mutate("INSERT INTO sessions (token, expires_at, user_id, auth_method) VALUES (?, ?, ?, ?)", [
			token,
			expiration,
			userId,
			"openid"
		]);
		clearExpiredSessions();
		return { url: `${return_url}/openid-cb?token=${token}` };
	} catch (error) {
		console.error("OpenID grant failed");
		debugSensitive("OpenID grant failed: %O", error);
		return { error: "openid-grant-failed" };
	}
}
function getServerHostname() {
	const auth = getAccountDb().first("select * from auth WHERE method = ? and active = 1", ["openid"]);
	if (auth && auth.extra_data) try {
		return JSON.parse(auth.extra_data).server_hostname;
	} catch (error) {
		console.error("Error parsing OpenID configuration");
		debugSensitive("Error parsing OpenID configuration: %O", error);
	}
	return null;
}
function isValidRedirectUrl(url) {
	const serverHostname = getServerHostname();
	if (!serverHostname) return false;
	try {
		const redirectUrl = new URL(url);
		const serverUrl = new URL(serverHostname);
		if (redirectUrl.hostname === serverUrl.hostname || redirectUrl.hostname === "localhost") return true;
		else return false;
	} catch {
		return false;
	}
}
var USERNAME_RE = /^[a-z0-9._-]{3,40}$/;
function normalizeUsername(username) {
	return typeof username === "string" ? username.trim().toLowerCase() : "";
}
function isValidUsername(username) {
	return USERNAME_RE.test(normalizeUsername(username));
}
function isValidUserPassword(password) {
	return typeof password === "string" && password.length >= 8;
}
var dummyHash;
async function getDummyHash() {
	if (!dummyHash) dummyHash = hashPassword("nfinance-dummy-password");
	return dummyHash;
}
function sessionExpiration() {
	const exp = configSchema.get("token_expiration");
	if (exp !== "never" && exp !== "openid-provider" && typeof exp === "number") return Math.floor(Date.now() / 1e3) + exp * 60;
	return -1;
}
function createSession(userId) {
	const accountDb = getAccountDb();
	const token = v4();
	accountDb.mutate("INSERT INTO sessions (token, expires_at, user_id, auth_method) VALUES (?, ?, ?, ?)", [
		token,
		sessionExpiration(),
		userId,
		"userpass"
	]);
	clearExpiredSessions();
	return token;
}
function findUser(username) {
	return getAccountDb().first(`SELECT id, user_name, password_hash, enabled FROM users
     WHERE user_name <> '' AND LOWER(user_name) = ?`, [normalizeUsername(username)]);
}
/**
* Cria a conta master e ativa o método userpass.
* Reutiliza a linha de utilizador original (user_name ''), para que os
* orçamentos que já existiam continuem a pertencer ao dono.
*/
async function setupMasterUser({ username, password, displayName }) {
	if (!isValidUsername(username)) return { error: "invalid-username" };
	if (!isValidUserPassword(password)) return { error: "password-too-short" };
	const hashed = await hashPassword(password);
	const name = normalizeUsername(username);
	const accountDb = getAccountDb();
	return accountDb.transaction(() => {
		accountDb.mutate("DELETE FROM auth");
		accountDb.mutate("INSERT INTO auth (method, display_name, extra_data, active) VALUES ('userpass', 'Usuário e senha', NULL, 1)");
		let userId = (accountDb.first("SELECT id FROM users WHERE user_name <> '' AND LOWER(user_name) = ?", [name]) || accountDb.first("SELECT id FROM users WHERE user_name = ''"))?.id;
		if (userId) accountDb.mutate(`UPDATE users SET user_name = ?, display_name = ?, password_hash = ?,
         owner = 1, role = 'ADMIN', enabled = 1 WHERE id = ?`, [
			name,
			displayName || name,
			hashed,
			userId
		]);
		else {
			userId = v4();
			accountDb.mutate(`INSERT INTO users (id, user_name, display_name, enabled, owner, role, password_hash)
         VALUES (?, ?, ?, 1, 1, 'ADMIN', ?)`, [
				userId,
				name,
				displayName || name,
				hashed
			]);
		}
		accountDb.mutate("DELETE FROM sessions");
		return { userId };
	});
}
async function bootstrapUserpass(settings) {
	const { error, userId } = await setupMasterUser(settings || {});
	if (error) return { error };
	return { token: createSession(userId) };
}
async function loginWithUserpass(username, password) {
	if (typeof password !== "string" || !password) return { error: "invalid-credentials" };
	const user = findUser(username);
	if (!user || !user.enabled || !user.password_hash) {
		await verifyPassword(password, await getDummyHash());
		return { error: "invalid-credentials" };
	}
	if (!await verifyPassword(password, user.password_hash)) return { error: "invalid-credentials" };
	return { token: createSession(user.id) };
}
async function setUserPassword(userId, newPassword) {
	if (!isValidUserPassword(newPassword)) return { error: "password-too-short" };
	const hashed = await hashPassword(newPassword);
	const accountDb = getAccountDb();
	accountDb.transaction(() => {
		accountDb.mutate("UPDATE users SET password_hash = ? WHERE id = ?", [hashed, userId]);
		accountDb.mutate("DELETE FROM sessions WHERE user_id = ?", [userId]);
		accountDb.mutate("DELETE FROM api_keys WHERE user_id = ?", [userId]);
	});
	return {};
}
async function changeOwnPassword(userId, currentPassword, newPassword) {
	const user = getAccountDb().first("SELECT password_hash FROM users WHERE id = ?", [userId]);
	if (!user?.password_hash || !await verifyPassword(currentPassword, user.password_hash)) return { error: "invalid-current-password" };
	return setUserPassword(userId, newPassword);
}
//#endregion
//#region src/db.js
var WrappedDatabase = class {
	constructor(db) {
		this.db = db;
	}
	/**
	* @param {string} sql
	* @param {(string | number)[]} params
	*/
	all(sql, params = []) {
		return this.db.prepare(sql).all(...params);
	}
	/**
	* @param {string} sql
	* @param {string[]} params
	*/
	first(sql, params = []) {
		const rows = this.all(sql, params);
		return rows.length === 0 ? null : rows[0];
	}
	/**
	* @param {string} sql
	*/
	exec(sql) {
		return this.db.exec(sql);
	}
	/**
	* @param {string} sql
	* @param {(string | number | null | undefined)[]} params
	*/
	mutate(sql, params = []) {
		const info = this.db.prepare(sql).run(...params);
		return {
			changes: info.changes,
			insertId: info.lastInsertRowid
		};
	}
	/**
	* @param {() => void} fn
	*/
	transaction(fn) {
		return this.db.transaction(fn)();
	}
	close() {
		this.db.close();
	}
};
/** @param {string} filename */
function openDatabase(filename) {
	return new WrappedDatabase(new Database(filename));
}
//#endregion
//#region src/account-db.js
var _accountDb;
function getAccountDb() {
	if (_accountDb === void 0) _accountDb = openDatabase(join(resolve(configSchema.get("serverFiles")), "account.sqlite"));
	return _accountDb;
}
function needsBootstrap() {
	return getAccountDb().all("SELECT * FROM auth").length === 0;
}
function listLoginMethods() {
	const rows = getAccountDb().all("SELECT method, display_name, active FROM auth");
	return rows.filter((f) => rows.length > 1 && configSchema.get("enforceOpenId") ? f.method === "openid" : true).map((r) => ({
		method: r.method,
		active: r.active,
		displayName: r.display_name
	}));
}
function isMultiuserMethod(method) {
	return method === "openid" || method === "userpass";
}
function getActiveLoginMethod() {
	const { method } = getAccountDb().first("SELECT method FROM auth WHERE active = 1") || {};
	return method;
}
function getLoginMethod(req) {
	if (typeof req !== "undefined" && (req.body || { loginMethod: null }).loginMethod && configSchema.get("allowedLoginMethods").includes(req.body.loginMethod)) {
		if (getAccountDb().first("SELECT method FROM auth WHERE method = ?", [req.body.loginMethod])) return req.body.loginMethod;
	}
	if (configSchema.get("loginMethod") === "header" && configSchema.get("allowedLoginMethods").includes("header")) return configSchema.get("loginMethod");
	return getActiveLoginMethod() || configSchema.get("loginMethod");
}
async function bootstrap(loginSettings, forced = false) {
	if (!loginSettings) return { error: "invalid-login-settings" };
	if ("userpass" in loginSettings) {
		if (!needsBootstrap()) return { error: "already-bootstrapped" };
		return bootstrapUserpass(loginSettings.userpass);
	}
	const passEnabled = "password" in loginSettings;
	const openIdEnabled = "openId" in loginSettings;
	const accountDb = getAccountDb();
	let passwordHash;
	if (passEnabled) {
		if (!isValidPassword(loginSettings.password)) return { error: "invalid-password" };
		passwordHash = await hashPassword(loginSettings.password);
	}
	accountDb.mutate("BEGIN TRANSACTION");
	try {
		const { countOfOwner } = accountDb.first(`SELECT count(*) as countOfOwner
   FROM users
   WHERE users.user_name <> '' and users.owner = 1`) || {};
		if (!forced && (!openIdEnabled || countOfOwner > 0)) {
			if (!needsBootstrap()) {
				accountDb.mutate("ROLLBACK");
				return { error: "already-bootstrapped" };
			}
		}
		if (!passEnabled && !openIdEnabled) {
			accountDb.mutate("ROLLBACK");
			return { error: "no-auth-method-selected" };
		}
		if (passEnabled && openIdEnabled && !forced) {
			accountDb.mutate("ROLLBACK");
			return { error: "max-one-method-allowed" };
		}
		if (passEnabled) setPasswordHash(passwordHash);
		if (openIdEnabled && forced) {
			const { error } = await bootstrapOpenId(loginSettings.openId);
			if (error) {
				accountDb.mutate("ROLLBACK");
				return { error };
			}
		}
		accountDb.mutate("COMMIT");
		return passEnabled ? await loginWithPassword(loginSettings.password) : {};
	} catch (error) {
		accountDb.mutate("ROLLBACK");
		throw error;
	}
}
function isAdmin(userId) {
	return hasPermission(userId, "ADMIN");
}
function hasPermission(userId, permission) {
	return getUserPermission(userId) === permission;
}
async function enableOpenID(loginSettings) {
	if (!loginSettings || !loginSettings.openId) return { error: "invalid-login-settings" };
	const { error } = await bootstrapOpenId(loginSettings.openId) || {};
	if (error) return { error };
	getAccountDb().transaction(() => {
		getAccountDb().mutate("DELETE FROM sessions");
		getAccountDb().mutate("DELETE FROM api_keys");
	});
}
async function disableOpenID(loginSettings) {
	if (!loginSettings || !loginSettings.password) return { error: "invalid-login-settings" };
	const accountDb = getAccountDb();
	const { extra_data: passwordHash } = accountDb.first("SELECT extra_data FROM auth WHERE method = ?", ["password"]) || {};
	if (!passwordHash) return { error: "invalid-password" };
	if (!loginSettings?.password) return { error: "invalid-password" };
	if (!await verifyPassword(loginSettings.password, passwordHash)) return { error: "invalid-password" };
	const { error } = await bootstrapPassword(loginSettings.password);
	if (error) return { error };
	try {
		accountDb.transaction(() => {
			accountDb.mutate("DELETE FROM sessions");
			accountDb.mutate("DELETE FROM api_keys");
			accountDb.mutate(`DELETE FROM user_access
                              WHERE user_access.user_id IN (
                                  SELECT users.id
                                  FROM users
                                  WHERE users.user_name <> ?
                              );`, [""]);
			accountDb.mutate("DELETE FROM users WHERE user_name <> ?", [""]);
			accountDb.mutate("DELETE FROM auth WHERE method = ?", ["openid"]);
		});
	} catch (err) {
		console.error("Error cleaning up openid information:", err);
		return { error: "database-error" };
	}
}
function getSession(token) {
	return getAccountDb().first(`SELECT sessions.*
     FROM sessions
     JOIN users ON users.id = sessions.user_id
     WHERE sessions.token = ? AND users.enabled = 1`, [token]);
}
function getUserInfo(userId) {
	return getAccountDb().first("SELECT * FROM users WHERE id = ?", [userId]);
}
function getUserPermission(userId) {
	const { role } = getAccountDb().first(`SELECT role FROM users
          WHERE users.id = ?`, [userId]) || { role: "" };
	return role;
}
function getServerPrefs() {
	return (getAccountDb().all("SELECT key, value FROM server_prefs") || []).reduce((prefs, row) => {
		prefs[row.key] = row.value;
		return prefs;
	}, {});
}
function setServerPrefs(prefs) {
	const accountDb = getAccountDb();
	if (!prefs) return;
	accountDb.transaction(() => {
		Object.entries(prefs).forEach(([key, value]) => {
			accountDb.mutate("INSERT INTO server_prefs (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value", [key, value]);
		});
	});
}
function clearExpiredSessions() {
	const clearThreshold = Math.floor(Date.now() / 1e3) - 3600;
	const deletedSessions = getAccountDb().mutate("DELETE FROM sessions WHERE expires_at <> -1 and expires_at < ?", [clearThreshold]).changes;
	console.log(`Deleted ${deletedSessions} old sessions`);
}
//#endregion
export { validateAuthHeader as A, getAllUsers as B, loginWithOpenIdFinalize as C, hashPassword as D, checkPassword as E, countUserAccess as F, getUserAccess as G, getOpenIDConfig as H, deleteUser as I, insertUser as J, getUserById as K, deleteUserAccess as L, addUserAccess as M, canAccessActiveFile as N, isValidPassword as O, checkFilePermission as P, validateRole as Q, deleteUserAccessByFileId as R, isValidRedirectUrl as S, changePassword as T, getOwnerCount as U, getFileById as V, getOwnerId as W, updateFileOwner as X, transferAllFilesFromUser as Y, updateUserWithRole as Z, isValidUsername as _, getActiveLoginMethod as a, setUserPassword as b, getUserInfo as c, listLoginMethods as d, needsBootstrap as f, isValidUserPassword as g, changeOwnPassword as h, getAccountDb as i, validateSession as j, loginWithPassword as k, isAdmin as l, openDatabase as m, disableOpenID as n, getLoginMethod as o, setServerPrefs as p, getUserByUsername as q, enableOpenID as r, getServerPrefs as s, bootstrap as t, isMultiuserMethod as u, loginWithUserpass as v, loginWithOpenIdSetup as w, setupMasterUser as x, normalizeUsername as y, getAllUserAccess as z };

//# sourceMappingURL=account-db-DNaHpKvL.js.map