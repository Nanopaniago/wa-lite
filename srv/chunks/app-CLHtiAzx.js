import { i as isBlockedIp, n as assertUrlAllowed, r as createSsrfDispatcher, t as configSchema } from "./load-config-D-6K5UFX.js";
import { A as validateAuthHeader, B as getAllUsers, C as loginWithOpenIdFinalize, D as hashPassword, E as checkPassword, F as countUserAccess, G as getUserAccess, H as getOpenIDConfig, I as deleteUser, J as insertUser, K as getUserById, L as deleteUserAccess, M as addUserAccess, N as canAccessActiveFile, O as isValidPassword, P as checkFilePermission, Q as validateRole, R as deleteUserAccessByFileId, S as isValidRedirectUrl, T as changePassword, U as getOwnerCount, V as getFileById, W as getOwnerId, X as updateFileOwner, Y as transferAllFilesFromUser, Z as updateUserWithRole, _ as isValidUsername, a as getActiveLoginMethod, b as setUserPassword, c as getUserInfo, d as listLoginMethods, f as needsBootstrap, g as isValidUserPassword, h as changeOwnPassword, i as getAccountDb, j as validateSession, k as loginWithPassword, l as isAdmin, m as openDatabase, n as disableOpenID, o as getLoginMethod, p as setServerPrefs, q as getUserByUsername, r as enableOpenID, s as getServerPrefs, t as bootstrap, u as isMultiuserMethod, v as loginWithUserpass, w as loginWithOpenIdSetup, y as normalizeUsername, z as getAllUserAccess } from "./account-db-DNaHpKvL.js";
import { dirname, isAbsolute, join, resolve, sep } from "node:path";
import fs, { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import createDebug from "debug";
import ipaddr from "ipaddr.js";
import { fetch } from "undici";
import { v4 } from "uuid";
import fs$1 from "node:fs/promises";
import cors from "cors";
import express from "express";
import rateLimit from "express-rate-limit";
import * as expressWinston from "express-winston";
import * as winston from "winston";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { AkahuClient } from "akahu";
import { sign } from "jws";
import crypto from "crypto";
import * as d from "date-fns";
import { PluggyClient } from "pluggy-sdk";
import { Buffer as Buffer$1 } from "node:buffer";
import murmurhash from "murmurhash";
import { fileDesc, messageDesc } from "@bufbuild/protobuf/codegenv2";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
//#region \0rolldown/runtime.js
var __defProp = Object.defineProperty;
var __exportAll = (all, no_symbols) => {
	let target = {};
	for (var name in all) __defProp(target, name, {
		get: all[name],
		enumerable: true
	});
	if (!no_symbols) __defProp(target, Symbol.toStringTag, { value: "Module" });
	return target;
};
//#endregion
//#region src/util/middlewares.ts
async function errorMiddleware(err, req, res, next) {
	debugSensitive$11("Error on %s %s: %O", req.method, req.baseUrl + req.path, err);
	if (res.headersSent) return next(/* @__PURE__ */ new Error("Request failed after response headers were sent"));
	console.log(`Error on endpoint %s`, {
		method: req.method,
		path: req.baseUrl + req.path,
		statusCode: 500
	});
	res.status(500).send({
		status: "error",
		reason: "internal-error"
	});
}
var debugSensitive$11 = createDebug("actual-sensitive:server");
var validateSessionMiddleware = async (req, res, next) => {
	const session = await validateSession(req, res);
	if (!session) return;
	res.locals = session;
	next();
};
var requestLoggerMiddleware = expressWinston.logger({
	transports: [new winston.transports.Console()],
	msg: "HTTP request",
	requestWhitelist: ["method", "path"],
	responseWhitelist: ["statusCode"],
	requestFilter: (req, key) => key === "path" ? req.baseUrl + req.path : req.method,
	format: winston.format.combine(...Object.prototype.hasOwnProperty.call(process.env, "NO_COLOR") ? [] : [winston.format.colorize()], winston.format.timestamp(), winston.format.printf((args) => {
		const { timestamp, level, meta } = args;
		const { res, req } = meta;
		return `${String(timestamp)} ${String(level)}: ${req.method} ${res.statusCode} ${req.path}`;
	}))
});
//#endregion
//#region src/util/validate-budget-session.ts
function validateBudgetSession(req, res) {
	const token = req.body?.token || req.headers["x-actual-token"];
	if (typeof token !== "string" || !token.startsWith("actual_")) return validateSession(req, res);
	const key = /^actual_[A-Za-z0-9_-]{43}$/.test(token) ? getAccountDb().first(`SELECT api_keys.id, api_keys.user_id
           FROM api_keys JOIN users ON users.id = api_keys.user_id
           WHERE api_keys.key_hash = ? AND users.enabled = 1`, [createHash("sha256").update(token).digest("hex")]) : null;
	if (!key) {
		res.status(401).send({
			status: "error",
			reason: "unauthorized"
		});
		return null;
	}
	const apiKeyFileIds = getAccountDb().all("SELECT file_id FROM api_key_budgets WHERE key_id = ?", [key.id]).map((budget) => budget.file_id).filter((fileId) => canAccessActiveFile(fileId, key.user_id));
	return {
		user_id: key.user_id,
		apiKeyFileIds
	};
}
function validateBankSyncSession(req, res, next) {
	const session = validateBudgetSession(req, res);
	if (!session) return;
	if ("apiKeyFileIds" in session && !session.apiKeyFileIds.includes(req.get("X-Actual-File-Id") ?? "")) {
		res.status(403).send({
			status: "error",
			reason: "file-access-denied"
		});
		return;
	}
	res.locals = session;
	next();
}
//#endregion
//#region src/app-account.js
var app$12 = express();
app$12.use(express.json());
app$12.use(express.urlencoded({ extended: true }));
app$12.use(errorMiddleware);
app$12.use(requestLoggerMiddleware);
var authRateLimiter = rateLimit({
	windowMs: 9e5,
	max: 5,
	legacyHeaders: false,
	standardHeaders: true,
	skipSuccessfulRequests: true,
	message: {
		status: "error",
		reason: "too-many-requests"
	}
});
app$12.get("/needs-bootstrap", (req, res) => {
	const availableLoginMethods = listLoginMethods();
	res.send({
		status: "ok",
		data: {
			bootstrapped: !needsBootstrap(),
			loginMethod: availableLoginMethods.length === 1 ? availableLoginMethods[0].method : getLoginMethod(),
			availableLoginMethods,
			multiuser: isMultiuserMethod(getActiveLoginMethod())
		}
	});
});
app$12.post("/bootstrap", authRateLimiter, async (req, res) => {
	const boot = await bootstrap(req.body);
	if (boot?.error) {
		res.status(400).send({
			status: "error",
			reason: boot?.error
		});
		return;
	}
	res.send({
		status: "ok",
		data: boot
	});
});
app$12.get("/login-methods", (req, res) => {
	const methods = listLoginMethods();
	res.send({
		status: "ok",
		methods
	});
});
app$12.post("/login", authRateLimiter, async (req, res) => {
	const loginMethod = getLoginMethod(req);
	console.log("Logging in via " + loginMethod);
	let tokenRes = null;
	switch (loginMethod) {
		case "header": {
			const headerVal = req.get("x-actual-password") || "";
			const obfuscated = "*".repeat(headerVal.length) || "No password provided.";
			console.debug("HEADER VALUE: " + obfuscated);
			if (headerVal === "") {
				res.send({
					status: "error",
					reason: "invalid-header"
				});
				return;
			} else if (validateAuthHeader(req)) tokenRes = await loginWithPassword(headerVal);
			else {
				res.send({
					status: "error",
					reason: "proxy-not-trusted"
				});
				return;
			}
			break;
		}
		case "openid": {
			if (!isValidRedirectUrl(req.body.returnUrl)) {
				res.status(400).send({
					status: "error",
					reason: "Invalid redirect URL"
				});
				return;
			}
			const { error, url } = await loginWithOpenIdSetup(req.body.returnUrl, req.body.password);
			if (error) {
				res.status(400).send({
					status: "error",
					reason: error
				});
				return;
			}
			res.send({
				status: "ok",
				data: { returnUrl: url }
			});
			return;
		}
		case "userpass":
			tokenRes = await loginWithUserpass(req.body.username, req.body.password);
			break;
		default: tokenRes = await loginWithPassword(req.body.password);
	}
	const { error, token } = tokenRes;
	if (error) {
		res.status(400).send({
			status: "error",
			reason: error
		});
		return;
	}
	res.send({
		status: "ok",
		data: { token }
	});
});
app$12.post("/logout", (req, res) => {
	const token = req.body?.token;
	if (typeof token !== "string" || !token) {
		res.status(400).send({
			status: "error",
			reason: "invalid-token"
		});
		return;
	}
	getAccountDb().mutate("DELETE FROM sessions WHERE token = ?", [token]);
	res.send({
		status: "ok",
		data: {}
	});
});
app$12.post("/change-password", authRateLimiter, async (req, res) => {
	const session = validateSession(req, res);
	if (!session) return;
	if (session.auth_method === "userpass") {
		const { error } = await changeOwnPassword(session.user_id, req.body.currentPassword, req.body.password);
		if (error) {
			res.status(400).send({
				status: "error",
				reason: error
			});
			return;
		}
		res.send({
			status: "ok",
			data: {}
		});
		return;
	}
	if (!isAdmin(session.user_id)) {
		res.status(403).send({
			status: "error",
			reason: "forbidden",
			details: "permission-not-found"
		});
		return;
	}
	if (session.auth_method !== "password") {
		res.status(403).send({
			status: "error",
			reason: "forbidden",
			details: "password-auth-not-active"
		});
		return;
	}
	if (!isValidPassword(req.body.currentPassword)) {
		res.status(400).send({
			status: "error",
			reason: "invalid-current-password"
		});
		return;
	}
	const { error } = await changePassword(req.body.password, req.body.currentPassword);
	if (error) {
		res.status(400).send({
			status: "error",
			reason: error
		});
		return;
	}
	res.send({
		status: "ok",
		data: {}
	});
});
app$12.post("/server-prefs", (req, res) => {
	const session = validateSession(req, res);
	if (!session) return;
	if (!isAdmin(session.user_id)) {
		res.status(403).send({
			status: "error",
			reason: "forbidden",
			details: "permission-not-found"
		});
		return;
	}
	const { prefs } = req.body || {};
	if (!prefs || typeof prefs !== "object") {
		res.status(400).send({
			status: "error",
			reason: "invalid-prefs"
		});
		return;
	}
	setServerPrefs(prefs);
	res.send({
		status: "ok",
		data: {}
	});
});
app$12.get("/validate", (req, res) => {
	const session = validateBudgetSession(req, res);
	if (session?.apiKeyFileIds) {
		res.send({
			status: "ok",
			data: {
				validated: true,
				loginMethod: "api-key"
			}
		});
		return;
	}
	if (session) {
		const user = getUserInfo(session.user_id);
		if (!user) {
			res.status(400).send({
				status: "error",
				reason: "User not found"
			});
			return;
		}
		res.send({
			status: "ok",
			data: {
				validated: true,
				userName: user?.user_name,
				permission: user?.role,
				userId: session?.user_id,
				displayName: user?.display_name,
				loginMethod: session?.auth_method,
				prefs: getServerPrefs()
			}
		});
	}
});
//#endregion
//#region src/app-admin.js
var app$11 = express();
app$11.use(express.json());
app$11.use(express.urlencoded({ extended: true }));
app$11.use(requestLoggerMiddleware);
app$11.get("/owner-created/", (req, res) => {
	try {
		const ownerCount = getOwnerCount();
		res.json(ownerCount > 0);
	} catch {
		res.status(500).json({ error: "Failed to retrieve owner count" });
	}
});
app$11.get("/users/", validateSessionMiddleware, (req, res) => {
	const users = getAllUsers();
	res.json(users.map((u) => ({
		...u,
		owner: u.owner === 1,
		enabled: u.enabled === 1
	})));
});
app$11.post("/users", validateSessionMiddleware, async (req, res) => {
	if (!isAdmin(res.locals.user_id)) {
		res.status(403).send({
			status: "error",
			reason: "forbidden",
			details: "permission-not-found"
		});
		return;
	}
	const { role, displayName, enabled, password } = req.body || {};
	let { userName } = req.body || {};
	const userpass = getActiveLoginMethod() === "userpass";
	if (userpass) {
		userName = normalizeUsername(userName);
		if (!isValidUsername(userName)) {
			res.status(400).send({
				status: "error",
				reason: "invalid-username",
				details: "Username must have 3-40 chars: a-z 0-9 . _ -"
			});
			return;
		}
		if (!isValidUserPassword(password)) {
			res.status(400).send({
				status: "error",
				reason: "password-too-short",
				details: "Password must have at least 8 characters"
			});
			return;
		}
	}
	if (!userName || !role) {
		res.status(400).send({
			status: "error",
			reason: `${!userName ? "user-cant-be-empty" : "role-cant-be-empty"}`,
			details: `${!userName ? "Username" : "Role"} cannot be empty`
		});
		return;
	}
	if (!validateRole(role)) {
		res.status(400).send({
			status: "error",
			reason: "role-does-not-exists",
			details: "Selected role does not exist"
		});
		return;
	}
	if (getUserByUsername(userName)) {
		res.status(400).send({
			status: "error",
			reason: "user-already-exists",
			details: `User ${userName} already exists`
		});
		return;
	}
	const userId = v4();
	insertUser(userId, userName, displayName || null, enabled ? 1 : 0, role, userpass ? await hashPassword(password) : null);
	res.status(200).send({
		status: "ok",
		data: { id: userId }
	});
});
app$11.patch("/users", validateSessionMiddleware, async (req, res) => {
	if (!isAdmin(res.locals.user_id)) {
		res.status(403).send({
			status: "error",
			reason: "forbidden",
			details: "permission-not-found"
		});
		return;
	}
	const { id, userName, role, displayName, enabled } = req.body || {};
	if (!userName || !role) {
		res.status(400).send({
			status: "error",
			reason: `${!userName ? "user-cant-be-empty" : "role-cant-be-empty"}`,
			details: `${!userName ? "Username" : "Role"} cannot be empty`
		});
		return;
	}
	if (!validateRole(role)) {
		res.status(400).send({
			status: "error",
			reason: "role-does-not-exists",
			details: "Selected role does not exist"
		});
		return;
	}
	const userIdInDb = getUserById(id);
	if (!userIdInDb) {
		res.status(400).send({
			status: "error",
			reason: "cannot-find-user-to-update",
			details: `Cannot find user ${userName} to update`
		});
		return;
	}
	const isOwner = userIdInDb === getOwnerId();
	const { password } = req.body || {};
	if (password !== void 0 && password !== null && password !== "") {
		if (getActiveLoginMethod() !== "userpass") {
			res.status(400).send({
				status: "error",
				reason: "password-auth-not-active",
				details: "Per-user passwords require the userpass login method"
			});
			return;
		}
		if (!isValidUserPassword(password)) {
			res.status(400).send({
				status: "error",
				reason: "password-too-short",
				details: "Password must have at least 8 characters"
			});
			return;
		}
	}
	updateUserWithRole(userIdInDb, getActiveLoginMethod() === "userpass" ? normalizeUsername(userName) : userName, displayName || null, isOwner ? 1 : enabled ? 1 : 0, isOwner ? "ADMIN" : role);
	if (password) await setUserPassword(userIdInDb, password);
	res.status(200).send({
		status: "ok",
		data: { id: userIdInDb }
	});
});
app$11.delete("/users", validateSessionMiddleware, async (req, res) => {
	if (!isAdmin(res.locals.user_id)) {
		res.status(403).send({
			status: "error",
			reason: "forbidden",
			details: "permission-not-found"
		});
		return;
	}
	const { ids } = req.body || {};
	let totalDeleted = 0;
	ids.forEach((item) => {
		const ownerId = getOwnerId();
		if (item === ownerId) return;
		deleteUserAccess(item);
		transferAllFilesFromUser(ownerId, item);
		const usersDeleted = deleteUser(item);
		totalDeleted += usersDeleted;
	});
	if (ids.length === totalDeleted) res.status(200).send({
		status: "ok",
		data: { someDeletionsFailed: false }
	});
	else res.status(400).send({
		status: "error",
		reason: "not-all-deleted",
		details: ""
	});
});
app$11.get("/access", validateSessionMiddleware, (req, res) => {
	const fileId = req.query.fileId;
	const { granted } = checkFilePermission(fileId, res.locals.user_id) || { granted: 0 };
	if (granted === 0 && !isAdmin(res.locals.user_id)) {
		res.status(403).send({
			status: "error",
			reason: "forbidden",
			details: "permission-not-found"
		});
		return false;
	}
	if (!getFileById(fileId)) {
		res.status(404).send({
			status: "error",
			reason: "invalid-file-id",
			details: "File not found at server"
		});
		return false;
	}
	const accesses = getUserAccess(fileId, res.locals.user_id, isAdmin(res.locals.user_id));
	res.json(accesses);
});
app$11.post("/access", (req, res) => {
	const userAccess = req.body || {};
	const session = validateSession(req, res);
	if (!session) return;
	const { granted } = checkFilePermission(userAccess.fileId, session.user_id) || { granted: 0 };
	if (granted === 0 && !isAdmin(session.user_id)) {
		res.status(400).send({
			status: "error",
			reason: "file-denied",
			details: "You don't have permissions over this file"
		});
		return;
	}
	if (!getFileById(userAccess.fileId)) {
		res.status(404).send({
			status: "error",
			reason: "invalid-file-id",
			details: "File not found at server"
		});
		return;
	}
	if (!userAccess.userId) {
		res.status(400).send({
			status: "error",
			reason: "user-cant-be-empty",
			details: "User cannot be empty"
		});
		return;
	}
	if (countUserAccess(userAccess.fileId, userAccess.userId) > 0) {
		res.status(400).send({
			status: "error",
			reason: "user-already-have-access",
			details: "User already have access"
		});
		return;
	}
	addUserAccess(userAccess.userId, userAccess.fileId);
	res.status(200).send({
		status: "ok",
		data: {}
	});
});
app$11.delete("/access", (req, res) => {
	const fileId = req.query.fileId;
	const session = validateSession(req, res);
	if (!session) return;
	const { granted } = checkFilePermission(fileId, session.user_id) || { granted: 0 };
	if (granted === 0 && !isAdmin(session.user_id)) {
		res.status(400).send({
			status: "error",
			reason: "file-denied",
			details: "You don't have permissions over this file"
		});
		return;
	}
	if (!getFileById(fileId)) {
		res.status(404).send({
			status: "error",
			reason: "invalid-file-id",
			details: "File not found at server"
		});
		return;
	}
	const { ids } = req.body || {};
	const totalDeleted = deleteUserAccessByFileId(ids, fileId);
	if (ids.length === totalDeleted) res.status(200).send({
		status: "ok",
		data: { someDeletionsFailed: false }
	});
	else res.status(400).send({
		status: "error",
		reason: "not-all-deleted",
		details: ""
	});
});
app$11.get("/access/users", validateSessionMiddleware, async (req, res) => {
	const fileId = req.query.fileId;
	const { granted } = checkFilePermission(fileId, res.locals.user_id) || { granted: 0 };
	if (granted === 0 && !isAdmin(res.locals.user_id)) {
		res.status(400).send({
			status: "error",
			reason: "file-denied",
			details: "You don't have permissions over this file"
		});
		return;
	}
	if (!getFileById(fileId)) {
		res.status(404).send({
			status: "error",
			reason: "invalid-file-id",
			details: "File not found at server"
		});
		return;
	}
	const users = getAllUserAccess(fileId);
	res.json(users);
});
app$11.post("/access/transfer-ownership/", validateSessionMiddleware, (req, res) => {
	const newUserOwner = req.body || {};
	const { granted } = checkFilePermission(newUserOwner.fileId, res.locals.user_id) || { granted: 0 };
	if (granted === 0 && !isAdmin(res.locals.user_id)) {
		res.status(400).send({
			status: "error",
			reason: "file-denied",
			details: "You don't have permissions over this file"
		});
		return;
	}
	if (!getFileById(newUserOwner.fileId)) {
		res.status(404).send({
			status: "error",
			reason: "invalid-file-id",
			details: "File not found at server"
		});
		return;
	}
	if (!newUserOwner.newUserId) {
		res.status(400).send({
			status: "error",
			reason: "user-cant-be-empty",
			details: "Username cannot be empty"
		});
		return;
	}
	if (getUserById(newUserOwner.newUserId) === 0) {
		res.status(400).send({
			status: "error",
			reason: "new-user-not-found",
			details: "New user not found"
		});
		return;
	}
	updateFileOwner(newUserOwner.newUserId, newUserOwner.fileId);
	res.status(200).send({
		status: "ok",
		data: {}
	});
});
app$11.use(errorMiddleware);
//#endregion
//#region src/app-gocardless/services/gocardless-api.ts
var debugSensitive$10 = createDebug("actual-sensitive:gocardless");
var BASE_URL$1 = "https://bankaccountdata.gocardless.com/api/v2";
var ALLOWED_ORIGIN = new URL(BASE_URL$1).origin;
var GoCardlessApiError = class extends Error {
	response;
	constructor(message, status, headers) {
		super(message);
		this.response = {
			status,
			headers
		};
	}
};
function isInvalidTokenResponse(data) {
	return typeof data === "object" && data !== null && "summary" in data && data.summary === "Invalid token";
}
var GoCardlessApi = class {
	#secretId;
	#secretKey;
	#token = null;
	constructor({ secretId, secretKey }) {
		this.#secretId = secretId;
		this.#secretKey = secretKey;
	}
	get secretId() {
		return this.#secretId;
	}
	get secretKey() {
		return this.#secretKey;
	}
	get token() {
		return this.#token;
	}
	set token(value) {
		this.#token = value;
	}
	async #request(endpoint, { method = "GET", body, isRetry = false } = {}) {
		const headers = {
			accept: "application/json",
			"Content-Type": "application/json"
		};
		if (this.#token) headers.Authorization = `Bearer ${this.#token}`;
		const url = new URL(`${BASE_URL$1}${endpoint}`);
		if (url.origin !== ALLOWED_ORIGIN || !url.pathname.startsWith("/api/v2/")) throw new Error(`Invalid GoCardless API endpoint: ${endpoint}`);
		const response = await fetch(url, {
			method,
			headers,
			signal: AbortSignal.timeout(2e4),
			...body ? { body: JSON.stringify(Object.fromEntries(Object.entries(body).filter(([, v]) => v != null))) } : {}
		});
		if (!response.ok) {
			const error = new GoCardlessApiError(`GoCardless API error: ${response.status}`, response.status, Object.fromEntries(response.headers.entries()));
			try {
				error.response.data = await response.json();
			} catch {}
			console.log(`GoCardless request failed: ${response.status}`);
			debugSensitive$10(`GoCardless ${method} ${endpoint} ${response.status}`, error.response.data ? JSON.stringify(error.response.data) : "(no body)");
			if (!isRetry && this.#token && response.status === 401 && isInvalidTokenResponse(error.response.data)) {
				this.#token = null;
				await this.generateToken();
				return this.#request(endpoint, {
					method,
					body,
					isRetry: true
				});
			}
			throw error;
		}
		return response.json();
	}
	async generateToken() {
		const data = await this.#request("/token/new/", {
			method: "POST",
			body: {
				secret_id: this.#secretId,
				secret_key: this.#secretKey
			}
		});
		this.#token = data.access;
		return data;
	}
	async exchangeToken({ refreshToken }) {
		const data = await this.#request("/token/refresh/", {
			method: "POST",
			body: { refresh: refreshToken }
		});
		this.#token = data.access;
		return data;
	}
	async getInstitutions({ country }) {
		return this.#request(`/institutions/?country=${country}`);
	}
	async getInstitutionById(id) {
		return this.#request(`/institutions/${id}/`);
	}
	async createRequisition({ redirectUrl, institutionId, agreement, userLanguage, reference, ssn, redirectImmediate, accountSelection }) {
		return this.#request("/requisitions/", {
			method: "POST",
			body: {
				redirect: redirectUrl,
				institution_id: institutionId,
				agreement,
				user_language: userLanguage,
				reference,
				ssn,
				redirect_immediate: redirectImmediate,
				account_selection: accountSelection
			}
		});
	}
	async getRequisitionById(requisitionId) {
		return this.#request(`/requisitions/${requisitionId}/`);
	}
	async deleteRequisition(requisitionId) {
		return this.#request(`/requisitions/${requisitionId}/`, { method: "DELETE" });
	}
	async createAgreement({ institutionId, maxHistoricalDays = 90, accessValidForDays = 90, accessScope = [
		"balances",
		"details",
		"transactions"
	] }) {
		return this.#request("/agreements/enduser/", {
			method: "POST",
			body: {
				institution_id: institutionId,
				max_historical_days: maxHistoricalDays,
				access_valid_for_days: accessValidForDays,
				access_scope: accessScope
			}
		});
	}
	async getAccountMetadata(accountId) {
		return this.#request(`/accounts/${accountId}/`);
	}
	async getAccountDetails(accountId) {
		return this.#request(`/accounts/${accountId}/details/`);
	}
	async getAccountBalances(accountId) {
		return this.#request(`/accounts/${accountId}/balances/`);
	}
	async getAccountTransactions({ accountId, dateFrom, dateTo }) {
		const params = new URLSearchParams();
		if (dateFrom) params.set("date_from", dateFrom);
		if (dateTo) params.set("date_to", dateTo);
		const query = params.toString();
		return this.#request(`/accounts/${accountId}/transactions/${query ? `?${query}` : ""}`);
	}
	async initSession({ redirectUrl, institutionId, maxHistoricalDays = 90, accessValidForDays = 90, userLanguage = "en", referenceId = null, ssn = null, redirectImmediate = false, accountSelection = false }) {
		const agreement = await this.createAgreement({
			institutionId,
			maxHistoricalDays: Number(maxHistoricalDays),
			accessValidForDays: Number(accessValidForDays)
		});
		return this.createRequisition({
			redirectUrl,
			institutionId,
			agreement: agreement.id,
			userLanguage,
			reference: referenceId,
			ssn,
			redirectImmediate,
			accountSelection
		});
	}
};
//#endregion
//#region src/app-gocardless/util/gocardless-error-details.ts
var MAX_TEXT_LENGTH = 500;
function isRecord$1(value) {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}
function readText(value) {
	if (typeof value !== "string") return;
	const trimmed = value.trim();
	return trimmed ? trimmed.slice(0, MAX_TEXT_LENGTH) : void 0;
}
function readSummaryAndDetail(value) {
	if (!isRecord$1(value)) return {};
	const summary = readText(value.summary);
	const detail = readText(value.detail);
	return {
		...summary ? { summary } : {},
		...detail ? { detail } : {}
	};
}
/**
* GoCardless answers either with a flat `{ summary, detail }` body or, for
* validation failures, with one such object per rejected field
* (`{ country: { summary, detail } }`). Only the first rejected field is
* reported — it is enough to tell the user what to correct.
*/
function readErrorBody(body) {
	const flat = readSummaryAndDetail(body);
	if (flat.summary || flat.detail) return flat;
	if (!isRecord$1(body)) return {};
	for (const value of Object.values(body)) {
		const nested = readSummaryAndDetail(value);
		if (nested.summary || nested.detail) return nested;
	}
	return {};
}
function findApiError(error) {
	if (error instanceof GoCardlessApiError) return error;
	if (error instanceof Error && "details" in error) {
		const { details } = error;
		if (details instanceof GoCardlessApiError) return details;
	}
}
/**
* Pulls the reason GoCardless rejected a request out of whatever error the
* service layer threw, so it can be surfaced in the UI instead of being
* collapsed into a generic message. Returns `undefined` for failures that did
* not come from the GoCardless API.
*/
function getGoCardlessErrorDetails(error) {
	const apiError = findApiError(error);
	if (!apiError) return;
	return {
		status: apiError.response.status,
		...readErrorBody(apiError.response.data)
	};
}
//#endregion
//#region src/app-gocardless/util/handle-error.ts
var debugSensitive$9 = createDebug("actual-sensitive:bank-sync");
function handleError(func) {
	return (req, res) => {
		func(req, res).catch((err) => {
			console.log("Error", req.method, req.baseUrl + req.path);
			debugSensitive$9("Error on %s %s: %O", req.method, req.baseUrl + req.path, err);
			const errorDetails = getGoCardlessErrorDetails(err);
			res.send({
				status: "ok",
				data: {
					error_code: "INTERNAL_ERROR",
					error_type: err.message ? err.message : "internal-error",
					...errorDetails ? { error_details: errorDetails } : {}
				}
			});
		});
	};
}
//#endregion
//#region src/services/secrets-service.js
/**
* An enum of valid secret names.
* @readonly
* @enum {string}
*/
var SecretName = {
	gocardless_secretId: "gocardless_secretId",
	gocardless_secretKey: "gocardless_secretKey",
	simplefin_token: "simplefin_token",
	simplefin_accessKey: "simplefin_accessKey",
	pluggyai_clientId: "pluggyai_clientId",
	pluggyai_clientSecret: "pluggyai_clientSecret",
	pluggyai_itemIds: "pluggyai_itemIds",
	akahu_userToken: "akahu_userToken",
	akahu_appToken: "akahu_appToken",
	enablebanking_applicationId: "enablebanking_applicationId",
	enablebanking_secretKey: "enablebanking_secretKey"
};
function getSecretKey(name, fileId) {
	return fileId == null ? name : `${name}:${fileId}`;
}
var SecretsDb = class {
	constructor() {
		this.debug = createDebug("actual:secrets-db");
		this.db = null;
	}
	open() {
		return getAccountDb();
	}
	set(name, value, fileId = null) {
		if (!this.db) this.db = this.open();
		const secretKey = getSecretKey(name, fileId);
		this.debug(`setting secret '${name}'`);
		return this.db.mutate(`INSERT OR REPLACE INTO secrets (name, value) VALUES (?, ?)`, [secretKey, value]);
	}
	get(name, fileId = null) {
		if (!this.db) this.db = this.open();
		const secretKey = getSecretKey(name, fileId);
		this.debug(`getting secret '${name}'`);
		return this.db.first(`SELECT value FROM secrets WHERE name = ?`, [secretKey]);
	}
	reset(name, fileId = null) {
		if (!this.db) this.db = this.open();
		const secretKey = getSecretKey(name, fileId);
		return {
			...this.db.mutate(`DELETE FROM secrets WHERE name = ?`, [secretKey]),
			deletedFrom: fileId == null ? "global" : "per-budget-file"
		};
	}
};
var secretsDb = new SecretsDb();
/**
* A service for managing secrets stored in `secretsDb`.
*/
var secretsService = {
	/**
	* Retrieves the active value of a secret by name.
	* @param {SecretName} name - The name of the secret to retrieve.
	* @param {string=} fileId - Budget file ID for this secret.
	* @returns {string|null} The value of the secret, or null if the secret does not exist.
	*/
	get: (name, fileId = null) => {
		return secretsDb.get(name, fileId)?.value ?? null;
	},
	/**
	* Sets the value of a secret by name.
	* @param {SecretName} name - The name of the secret to set.
	* @param {string} value - The value to set for the secret.
	* @param {string=} fileId - Budget file ID for this secret.
	* @returns {Object}
	*/
	set: (name, value, fileId = null) => {
		return secretsDb.set(name, value, fileId);
	},
	/**
	* @param {SecretName} name
	* @param {string|null} [fileId]
	*/
	reset: (name, fileId = null) => {
		return secretsDb.reset(name, fileId);
	},
	/**
	* Determines whether a secret with the given name exists.
	* @param {SecretName} name - The name of the secret to check for existence.
	* @param {string=} fileId - Budget file ID for this secret.
	* @returns {boolean} True if a secret with the given name exists, false otherwise.
	*/
	exists: (name, fileId = null) => {
		return secretsService.get(name, fileId) !== null;
	}
};
//#endregion
//#region src/util/mutex.ts
var createMutex = () => {
	let mutex = Promise.resolve();
	return (operation) => new Promise((resolve, reject) => {
		mutex = mutex.finally(() => {
			try {
				return operation().then(resolve, reject);
			} catch {}
		});
	});
};
//#endregion
//#region src/app-akahu/app-akahu.ts
var app$10 = express();
app$10.use(express.json());
app$10.use(requestLoggerMiddleware);
app$10.use(validateSessionMiddleware);
app$10.post("/status", handleError(async (_req, res) => {
	const userToken = secretsService.get(SecretName.akahu_userToken);
	const appToken = secretsService.get(SecretName.akahu_appToken);
	const configured = userToken != null && appToken != null;
	res.send({
		status: "ok",
		data: { configured }
	});
}));
app$10.post("/accounts", handleError(async (_req, res) => {
	const userToken = secretsService.get(SecretName.akahu_userToken);
	const appToken = secretsService.get(SecretName.akahu_appToken);
	if (!userToken || !appToken) {
		res.send({
			status: "ok",
			data: { error: "Missing user or app token" }
		});
		return;
	}
	try {
		const accounts = await new AkahuClient({ appToken }).accounts.list(userToken);
		res.send({
			status: "ok",
			data: { accounts }
		});
	} catch (error) {
		const errorMessage = error instanceof Error && error.message ? error.message : String(error);
		res.send({
			status: "error",
			data: { error: errorMessage }
		});
	}
}));
app$10.post("/transactions", handleError(async (req, res) => {
	const { accountId, startDate } = req.body || {};
	if (!accountId || !startDate) return res.send({
		status: "error",
		data: { error: "accountId and startDate are required" }
	});
	const userToken = secretsService.get(SecretName.akahu_userToken);
	const appToken = secretsService.get(SecretName.akahu_appToken);
	if (!userToken || !appToken) {
		res.send({
			status: "ok",
			data: { error: "Missing user or app token" }
		});
		return;
	}
	try {
		const akahu = new AkahuClient({ appToken });
		const account = await getRefreshedAccount(akahu, userToken, accountId);
		if (!account) return res.send({
			status: "error",
			data: { error: "Account not found" }
		});
		if (!account.balance) return res.send({
			status: "error",
			data: { error: "Account balance unavailable" }
		});
		const now = /* @__PURE__ */ new Date();
		const endDate = new Date(now.getFullYear(), now.getMonth() + 1, 1).toISOString();
		const startDateObj = new Date(Math.min(getNZStartOfDay(startDate).getTime(), now.getTime()));
		const transactions = [];
		let cursor = void 0;
		do {
			const { items, cursor: nextCursor } = await akahu.accounts.listTransactions(userToken, accountId, {
				start: (/* @__PURE__ */ new Date(startDateObj.getTime() - 1)).toISOString(),
				end: endDate,
				cursor
			});
			transactions.push(...items);
			cursor = nextCursor && nextCursor.next ? nextCursor.next : void 0;
		} while (cursor);
		const pendingTransactions = await akahu.accounts.listPendingTransactions(userToken, accountId);
		const date = getDate$2(account.refreshed?.balance ? new Date(account.refreshed.balance) : /* @__PURE__ */ new Date());
		const currentBalance = convertToCents(account.balance.current);
		const balances = [{
			balanceAmount: {
				amount: currentBalance,
				currency: account.balance.currency
			},
			balanceType: "expected",
			referenceDate: date
		}];
		if (account.balance.available) balances.push({
			balanceAmount: {
				amount: convertToCents(account.balance.available),
				currency: account.balance.currency
			},
			balanceType: "interimAvailable",
			referenceDate: date
		});
		const all = [];
		const booked = [];
		const pending = [];
		for (const trans of transactions) if (new Date(trans.date) >= startDateObj) {
			const processedTrans = processTransaction(trans, account);
			booked.push(processedTrans);
			all.push(processedTrans);
		}
		for (const trans of pendingTransactions) if (new Date(trans.date) >= startDateObj) {
			const processedTrans = processPendingTransaction(trans, account);
			pending.push(processedTrans);
			all.push(processedTrans);
		}
		const sortFunction = (a, b) => b.sortOrder - a.sortOrder;
		const bookedSorted = booked.sort(sortFunction);
		const pendingSorted = pending.sort(sortFunction);
		const allSorted = all.sort(sortFunction);
		res.send({
			status: "ok",
			data: {
				balances,
				startingBalance: currentBalance,
				transactions: {
					all: allSorted,
					booked: bookedSorted,
					pending: pendingSorted
				}
			}
		});
	} catch (error) {
		const errorMessage = error instanceof Error && error.message ? error.message : String(error);
		res.send({
			status: "error",
			data: { error: "Failed to fetch transactions: " + errorMessage }
		});
	}
}));
var runRefresh = createMutex();
function getRefreshedAccount(akahu, userToken, accountId) {
	return runRefresh(async () => {
		let account = await akahu.accounts.get(userToken, accountId);
		if (!account) return null;
		else if (!shouldRefreshAccount(account.refreshed?.transactions)) return account;
		await akahu.accounts.refreshAll(userToken);
		for (let i = 0; i < 5; i++) {
			await new Promise((resolve) => setTimeout(resolve, 3e3));
			account = await akahu.accounts.get(userToken, accountId);
			if (!account) return null;
			else if (!shouldRefreshAccount(account.refreshed?.transactions)) {
				await new Promise((resolve) => setTimeout(resolve, 3e3));
				break;
			}
		}
		return account;
	});
}
function getNZStartOfDay(startDate) {
	if (!/^\d{4}-\d{2}-\d{2}$/.test(startDate)) return new Date(startDate);
	const wallClock = (/* @__PURE__ */ new Date(`${startDate}T00:00:00Z`)).getTime();
	const guess = wallClock - getNZOffset(new Date(wallClock));
	return new Date(wallClock - getNZOffset(new Date(guess)));
}
function getNZOffset(date) {
	const parts = Object.fromEntries(dateTimePartsFormatNZ.formatToParts(date).map((part) => [part.type, Number(part.value)]));
	return Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second) - Math.floor(date.getTime() / 1e3) * 1e3;
}
var dateTimePartsFormatNZ = new Intl.DateTimeFormat("en-US", {
	timeZone: "Pacific/Auckland",
	hourCycle: "h23",
	year: "numeric",
	month: "numeric",
	day: "numeric",
	hour: "numeric",
	minute: "numeric",
	second: "numeric"
});
function getDate$2(date) {
	const parts = dateTimeFormatNZ.formatToParts(date);
	const month = parts[0].value;
	const day = parts[2].value;
	return `${parts[4].value}-${month}-${day}`;
}
var dateTimeFormatNZ = new Intl.DateTimeFormat("en-US", {
	timeZone: "Pacific/Auckland",
	year: "numeric",
	month: "2-digit",
	day: "2-digit"
});
function convertToCents(amount) {
	return Math.round(amount * 100);
}
function getPayeeName$1(trans) {
	return getMerchantName(trans) ?? getOtherAccount(trans) ?? trans.description;
}
function getMerchantName(trans) {
	if ("merchant" in trans && trans.merchant) return trans.merchant.name;
}
function getOtherAccount(trans) {
	if ("meta" in trans && trans.meta) return trans.meta.other_account ?? void 0;
}
function processPendingTransaction(trans, account) {
	const transactionDate = new Date(trans.date);
	return {
		...trans,
		booked: false,
		date: getDate$2(transactionDate),
		payeeName: getPayeeName$1(trans),
		merchant: { name: getOtherAccount(trans) ?? "" },
		notes: trans.description,
		sortOrder: transactionDate.getTime(),
		transactionAmount: {
			amount: Math.round(trans.amount * 100) / 100,
			currency: account.balance?.currency ?? "NZD"
		}
	};
}
function processTransaction(trans, account) {
	let category = void 0;
	if ("category" in trans && trans.category) category = trans.category.name;
	const merchant = "merchant" in trans && trans.merchant ? trans.merchant : { name: getOtherAccount(trans) ?? "" };
	return {
		...processPendingTransaction(trans, account),
		merchant,
		category,
		booked: true,
		transactionId: trans._id
	};
}
var AKAHU_TRANSACTION_REFRESH_INTERVAL_MS = 36e5;
function shouldRefreshAccount(refreshedAt) {
	if (!refreshedAt) return false;
	const refreshedAtTime = Date.parse(refreshedAt);
	return Number.isFinite(refreshedAtTime) && Date.now() - refreshedAtTime > AKAHU_TRANSACTION_REFRESH_INTERVAL_MS;
}
//#endregion
//#region src/util/paths.ts
var ID_REGEX = /^[a-zA-Z0-9_-]+$/;
function isValidFileId(id) {
	return ID_REGEX.test(id);
}
function isValidGroupId(id) {
	return ID_REGEX.test(id);
}
function getPathForUserFile(fileId) {
	const userFilesDir = resolve(configSchema.get("userFiles"));
	const filePath = resolve(userFilesDir, `file-${fileId}.blob`);
	const prefix = userFilesDir.endsWith(sep) ? userFilesDir : userFilesDir + sep;
	if (!filePath.startsWith(prefix)) throw new Error("Invalid file id");
	return filePath;
}
function getPathForGroupFile(groupId) {
	return join(resolve(configSchema.get("userFiles")), `group-${groupId}.sqlite`);
}
//#endregion
//#region src/app-api-keys.ts
var app$9 = express();
app$9.use(express.json());
app$9.use(requestLoggerMiddleware);
app$9.use(validateSessionMiddleware);
app$9.use((_req, res, next) => {
	res.set("Cache-Control", "no-store");
	next();
});
app$9.post("/", (req, res) => {
	const { name: rawName, fileIds } = req.body ?? {};
	const name = typeof rawName === "string" ? rawName.trim() : "";
	if (!name || name.length > 100 || !Array.isArray(fileIds) || fileIds.length === 0 || !fileIds.every((id) => typeof id === "string" && isValidFileId(id)) || new Set(fileIds).size !== fileIds.length) {
		res.status(400).send({
			status: "error",
			reason: "invalid-api-key"
		});
		return;
	}
	const userId = res.locals.user_id;
	if (!fileIds.every((id) => canAccessActiveFile(id, userId))) {
		res.status(403).send({
			status: "error",
			reason: "file-access-denied"
		});
		return;
	}
	const id = randomUUID();
	const key = `actual_${randomBytes(32).toString("base64url")}`;
	const keyHash = createHash("sha256").update(key).digest("hex");
	const createdAt = Math.floor(Date.now() / 1e3);
	const db = getAccountDb();
	db.transaction(() => {
		db.mutate(`INSERT INTO api_keys (id, user_id, name, key_hash, created_at)
       VALUES (?, ?, ?, ?, ?)`, [
			id,
			userId,
			name,
			keyHash,
			createdAt
		]);
		for (const fileId of fileIds) db.mutate("INSERT INTO api_key_budgets (key_id, file_id) VALUES (?, ?)", [id, fileId]);
	});
	res.status(201).send({
		status: "ok",
		data: {
			id,
			name,
			fileIds,
			createdAt,
			key
		}
	});
});
app$9.get("/", (_req, res) => {
	const keys = getAccountDb().all(`SELECT id, name, created_at AS createdAt,
       (SELECT json_group_array(file_id) FROM api_key_budgets WHERE key_id = api_keys.id) AS fileIds
     FROM api_keys WHERE user_id = ? ORDER BY created_at DESC, id`, [res.locals.user_id]);
	res.send({
		status: "ok",
		data: keys.map(({ fileIds, ...key }) => ({
			...key,
			fileIds: JSON.parse(fileIds)
		}))
	});
});
app$9.delete("/:id", (req, res) => {
	const { changes } = getAccountDb().mutate("DELETE FROM api_keys WHERE id = ? AND user_id = ?", [req.params.id, res.locals.user_id]);
	if (changes === 0) {
		res.status(404).send({
			status: "error",
			reason: "api-key-not-found"
		});
		return;
	}
	res.send({ status: "ok" });
});
app$9.use(errorMiddleware);
//#endregion
//#region src/app-cors-proxy.js
var debugSensitive$8 = createDebug("actual-sensitive:cors-proxy");
var app$8 = express();
app$8.use(express.json());
app$8.use(requestLoggerMiddleware);
app$8.use(rateLimit({
	windowMs: 6e4,
	max: 25,
	legacyHeaders: false,
	standardHeaders: true
}));
var allowlistedRepos = [];
var lastAllowlistFetch = 0;
var ALLOWLIST_CACHE_TTL = 3e5;
async function fetchAllowlist() {
	const now = Date.now();
	if (now - lastAllowlistFetch < ALLOWLIST_CACHE_TTL && allowlistedRepos.length > 0) return allowlistedRepos;
	try {
		const response = await fetch("https://raw.githubusercontent.com/actualbudget/plugin-store/refs/heads/main/plugins.json");
		if (!response.ok) throw new Error(`Failed to fetch allowlist: ${response.status}`);
		allowlistedRepos = (await response.json()).map((plugin) => plugin.url);
		lastAllowlistFetch = now;
		console.log("Updated plugin allowlist:", allowlistedRepos);
		return allowlistedRepos;
	} catch (error) {
		console.error("Failed to fetch plugin allowlist:", error);
		allowlistedRepos = [];
		return allowlistedRepos;
	}
}
/**
* Return true only if the URL is on an allowlist and not a local/private address.
*/
function isUrlAllowed(targetUrl) {
	try {
		const url = new URL(targetUrl);
		const hostname = url.hostname;
		if (isBlockedIp(hostname)) {
			console.warn(`Blocked request to private/localhost IP: ${hostname}`);
			return false;
		}
		if (targetUrl === "https://raw.githubusercontent.com/actualbudget/plugin-store/refs/heads/main/plugins.json") return true;
		for (const repoUrl of allowlistedRepos) try {
			const { pathname } = new URL(repoUrl);
			const [, repoOwner, repoName] = pathname.split("/");
			if (targetUrl === repoUrl || targetUrl.startsWith(repoUrl + "/") || hostname === "api.github.com" && (url.pathname === `/repos/${repoOwner}/${repoName}` || url.pathname.startsWith(`/repos/${repoOwner}/${repoName}/`)) || hostname === "raw.githubusercontent.com" && url.pathname.startsWith(`/${repoOwner}/${repoName}/`) || hostname === "github.com" && url.pathname.startsWith(`/${repoOwner}/${repoName}/releases/`)) return true;
		} catch (e) {
			console.warn("Invalid repository URL in allowlist:", repoUrl, e.message);
		}
		return false;
	} catch (e) {
		console.warn("Invalid target URL");
		debugSensitive$8("Invalid target URL %s: %O", targetUrl, e);
		return false;
	}
}
app$8.use("/", async (req, res) => {
	if (req.method === "OPTIONS") {
		res.set("Access-Control-Allow-Origin", "*");
		res.set("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS");
		res.set("Access-Control-Allow-Headers", "Content-Type, X-Actual-Token");
		res.set("Access-Control-Max-Age", "600");
		return res.status(204).end();
	}
	const targetUrlString = req.query.url;
	if (!targetUrlString) return res.status(400).json({ error: "Missing url parameter" });
	if (!await validateSession(req, res)) return;
	let url;
	try {
		url = new URL(targetUrlString);
	} catch {
		return res.status(400).json({ error: "Invalid url parameter" });
	}
	try {
		await fetchAllowlist();
	} catch (error) {
		console.error("Failed to fetch allowlist:", error);
		return res.status(403).json({
			error: "URL not allowed",
			message: "Unable to verify allowlist"
		});
	}
	if (!isUrlAllowed(url.href)) {
		console.warn("Blocked request to unauthorized URL");
		debugSensitive$8("Blocked request to unauthorized URL: %s", url.href);
		return res.status(403).json({
			error: "URL not allowed",
			message: "Only allowlisted plugin repositories are allowed (localhost only in development)"
		});
	}
	try {
		const { method = "GET", headers: customHeaders = {} } = req.body || {};
		if (typeof method !== "string") return res.status(400).json({ error: "Invalid method parameter" });
		const methodNormalized = method.toUpperCase();
		if (!["GET", "HEAD"].includes(methodNormalized)) return res.status(405).json({ error: "Method not allowed" });
		const requestHeaders = {
			...req.headers,
			...customHeaders,
			host: url.host
		};
		delete requestHeaders["x-actual-token"];
		delete requestHeaders["content-length"];
		delete requestHeaders["cookie"];
		delete requestHeaders["cookie2"];
		const githubToken = configSchema.get("github.token");
		if (githubToken && (url.hostname === "api.github.com" || url.hostname === "raw.githubusercontent.com" || url.hostname === "github.com" && url.pathname.includes("/releases/"))) {
			requestHeaders["Authorization"] = `Bearer ${githubToken}`;
			requestHeaders["User-Agent"] = "Actual-Budget-Plugin-System";
			console.log(`Using GitHub authentication for request to: ${url.hostname}`);
		}
		const response = await fetch(url.href, {
			method: methodNormalized,
			headers: requestHeaders
		});
		const contentType = response.headers.get("content-type") || "application/octet-stream";
		res.set("Access-Control-Allow-Origin", "*");
		res.status(response.status);
		const urlString = url.toString().toLowerCase();
		if (contentType?.includes("application/json") || urlString.includes(".json") || urlString.includes("/manifest") || urlString.includes("manifest.json") || urlString.includes("package.json")) {
			res.set("Content-Type", "application/json");
			const text = await response.text();
			try {
				res.json(JSON.parse(text));
			} catch {
				res.set("Content-Type", contentType || "text/plain");
				res.send(text);
			}
		} else if (contentType?.includes("text/")) {
			res.set("Content-Type", contentType);
			const text = await response.text();
			res.send(text);
		} else {
			res.set("Content-Type", "application/json");
			const buffer = await response.arrayBuffer();
			const binaryData = {
				data: Array.from(new Uint8Array(buffer)),
				contentType,
				isBinary: true
			};
			res.json(binaryData);
		}
	} catch (err) {
		res.status(500).json({
			error: "Error proxying request",
			details: err.message
		});
	}
});
//#endregion
//#region src/util/mobile-app-return.ts
var MOBILE_APP_URL = "actualbudget://localhost";
var MOBILE_APP_RETURN_PAGE_HTML = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Actual</title>
  </head>
  <body>
    <script>
      window.location.replace('${MOBILE_APP_URL}');
    <\/script>

    <p>All done. You can now return to the Actual app.</p>
    <p><a href="${MOBILE_APP_URL}">Return to Actual</a></p>
  </body>
</html>`;
//#endregion
//#region src/app-enablebanking/utils/errors.ts
var debugSensitive$7 = createDebug("actual-sensitive:enable-banking");
var debug$2 = createDebug("actual:enable-banking:errors");
var EnableBankingError = class extends Error {
	error_type;
	error_code;
	constructor(error_type, error_code, message) {
		super(message || `Enable Banking error: ${error_type} - ${error_code}`);
		this.name = "EnableBankingError";
		this.error_type = error_type;
		this.error_code = error_code;
	}
};
function handleEnableBankingError(statusCode, body) {
	const bodyStr = typeof body === "string" ? body : JSON.stringify(body ?? "unknown");
	debug$2("Enable Banking API error: status=%d", statusCode);
	debugSensitive$7("Enable Banking API error: status=%d body=%s", statusCode, bodyStr);
	const parsed = typeof body === "object" && body !== null ? Object.fromEntries(Object.entries(body)) : {};
	const message = typeof parsed.message === "string" ? parsed.message : bodyStr;
	const errorType = typeof parsed.error === "string" ? parsed.error : "UNKNOWN";
	if (statusCode === 401 || statusCode === 403) return new EnableBankingError(message, "INVALID_ACCESS_TOKEN", message);
	if (statusCode === 429) return new EnableBankingError(message, "RATE_LIMIT_EXCEEDED", message);
	if (statusCode === 404) return new EnableBankingError(message, "NOT_FOUND", message);
	if (statusCode >= 400 && statusCode < 500) {
		const lowerErrorType = (errorType || "").toLowerCase();
		const lowerMessage = (message || "").toLowerCase();
		if (lowerErrorType === "closed_session" || lowerErrorType === "expired_session" || lowerMessage.includes("session") || lowerMessage.includes("expired")) return new EnableBankingError(message, "INVALID_ACCESS_TOKEN", message);
		return new EnableBankingError(message, "INVALID_INPUT", message);
	}
	return new EnableBankingError(message, "INTERNAL_ERROR", message);
}
//#endregion
//#region src/app-enablebanking/utils/jwt.ts
function getJWTHeader(applicationId) {
	return {
		typ: "JWT",
		alg: "RS256",
		kid: applicationId
	};
}
function getJWTBody(exp = 3600) {
	const timestamp = Math.floor(Date.now() / 1e3);
	return {
		iss: "enablebanking.com",
		aud: "api.enablebanking.com",
		iat: timestamp,
		exp: timestamp + exp
	};
}
function getJWT(applicationId, secretKey, exp = 3600) {
	return sign({
		header: getJWTHeader(applicationId),
		payload: getJWTBody(exp),
		secret: secretKey
	});
}
//#endregion
//#region src/app-enablebanking/services/enablebanking-service.ts
var debugSensitive$6 = createDebug("actual-sensitive:enable-banking");
var debug$1 = createDebug("actual:enable-banking:service");
var BASE_URL = "https://api.enablebanking.com";
function getCredentials() {
	const applicationId = secretsService.get(SecretName.enablebanking_applicationId);
	const secretKey = secretsService.get(SecretName.enablebanking_secretKey);
	if (!applicationId || !secretKey) throw new EnableBankingError("INVALID_INPUT", "NOT_CONFIGURED", "Enable Banking is not configured");
	return {
		applicationId,
		secretKey
	};
}
function getAuthorizationHeader() {
	const { applicationId, secretKey } = getCredentials();
	return `Bearer ${getJWT(applicationId, secretKey)}`;
}
var REQUEST_TIMEOUT_MS = 3e4;
async function request(method, path, body, authHeaderOverride, psuHeaders) {
	const url = `${BASE_URL}${path}`;
	debug$1("%s request", method);
	debugSensitive$6("%s %s", method, url);
	const headers = {
		Authorization: authHeaderOverride ?? getAuthorizationHeader(),
		"Content-Type": "application/json"
	};
	if (psuHeaders) {
		for (const [key, value] of Object.entries(psuHeaders)) if (value) headers[key] = value;
	}
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
	const options = {
		method,
		headers,
		signal: controller.signal
	};
	if (body !== void 0) options.body = JSON.stringify(body);
	let response;
	try {
		response = await fetch(url, options);
	} catch (error) {
		if (error instanceof Error && error.name === "AbortError") throw new EnableBankingError("TIMED_OUT", "TIMED_OUT", "Request timed out");
		throw error;
	} finally {
		clearTimeout(timer);
	}
	if (!response.ok) {
		let responseBody;
		try {
			responseBody = await response.json();
		} catch {
			responseBody = await response.text().catch(() => "unknown");
		}
		throw handleEnableBankingError(response.status, responseBody);
	}
	return await response.json();
}
var SEPA_PREFIX_RE = /^(?:EREF|KREF|MREF|CRED|DBTR|CDTR|SVWZ|SVCL|PURP|RTRN|REJT|REFE|SDVA|INDA|NTAV|ULTC|ULTD|ULTB|ABWA|ABWE|IBAN|BIC|COAM|OAMT|REMI|SQTP|ROC)\+/;
function stripSepaPrefix(s) {
	return s.replace(SEPA_PREFIX_RE, "").trim();
}
function cleanRemittanceArray(arr) {
	return arr.map(stripSepaPrefix).filter(Boolean);
}
function deriveTransactionId(tx, derivedIdCounts) {
	const content = JSON.stringify([
		tx.transaction_date || tx.value_date || tx.booking_date || "",
		tx.transaction_amount.amount,
		tx.transaction_amount.currency,
		tx.credit_debit_indicator ?? "",
		tx.creditor?.name ?? "",
		tx.debtor?.name ?? "",
		tx.remittance_information ?? []
	]);
	const base = `derived-${createHash("sha256").update(content).digest("hex").slice(0, 32)}`;
	const count = derivedIdCounts.get(base) ?? 0;
	derivedIdCounts.set(base, count + 1);
	return count === 0 ? base : `${base}-${count}`;
}
function normalizeTransactions(transactions) {
	const normalized = transactions.map(normalizeTransaction);
	const derivedIdCounts = /* @__PURE__ */ new Map();
	for (const isBooked of [true, false]) for (const tx of normalized) if (!tx.transactionId && tx.booked === isBooked && isImportableTransaction(tx)) tx.transactionId = deriveTransactionId(tx, derivedIdCounts);
	return normalized;
}
function normalizeTransaction(tx) {
	const transactionId = tx.entry_reference || tx.transaction_id || "";
	const bookingDate = tx.booking_date || tx.value_date || tx.transaction_date || "";
	const valueDate = tx.value_date;
	let payeeName = "";
	if (tx.credit_debit_indicator === "CRDT") payeeName = tx.debtor?.name || "";
	else if (tx.credit_debit_indicator === "DBIT") payeeName = tx.creditor?.name || "";
	else payeeName = tx.creditor?.name || tx.debtor?.name || "";
	const cleanedAll = tx.remittance_information ? cleanRemittanceArray(tx.remittance_information) : [];
	if (!payeeName) payeeName = cleanedAll[0] || "";
	const remittanceInformationUnstructured = cleanedAll.length > 0 ? cleanedAll.join(" ") : void 0;
	const trimmedAmount = tx.transaction_amount.amount.trim();
	let signedAmount;
	if (tx.credit_debit_indicator === "DBIT") signedAmount = "-" + trimmedAmount.replace(/^[+-]/, "");
	else if (tx.credit_debit_indicator === "CRDT") signedAmount = trimmedAmount.replace(/^[+-]/, "");
	else signedAmount = trimmedAmount;
	return {
		...tx,
		transactionId,
		date: bookingDate,
		bookingDate,
		valueDate,
		transactionAmount: {
			amount: signedAmount,
			currency: tx.transaction_amount.currency
		},
		payeeName,
		notes: remittanceInformationUnstructured,
		remittanceInformationUnstructured,
		booked: tx.status !== "PDNG"
	};
}
var IMPORTABLE_DATE_REGEX = /^\d{4}-\d{2}-\d{2}$/;
function isImportableTransaction(tx) {
	const amount = tx.transactionAmount.amount.trim();
	return IMPORTABLE_DATE_REGEX.test(tx.date) && amount !== "" && Number.isFinite(Number(amount));
}
function normalizeBalance(bal) {
	return {
		balanceAmount: {
			amount: Math.round(parseFloat(bal.balance_amount.amount) * 100),
			currency: bal.balance_amount.currency
		},
		balanceType: bal.balance_type,
		referenceDate: bal.reference_date
	};
}
function normalizeAccount(account, aspsp) {
	return {
		account_id: account.uid,
		name: account.name || account.account_id?.iban || account.uid,
		institution: aspsp?.name || account.account_servicer?.name || "Unknown",
		currency: account.currency,
		iban: account.account_id?.iban
	};
}
var enableBankingService = {
	isConfigured() {
		const applicationId = secretsService.get(SecretName.enablebanking_applicationId);
		const secretKey = secretsService.get(SecretName.enablebanking_secretKey);
		return !!(applicationId && secretKey);
	},
	async validateCredentials(applicationId, secretKey) {
		return request("GET", "/application", void 0, `Bearer ${getJWT(applicationId, secretKey)}`);
	},
	async getApplication() {
		return request("GET", "/application");
	},
	async getAspsps(country) {
		return request("GET", `/aspsps${country ? `?country=${encodeURIComponent(country)}` : ""}`);
	},
	async startAuth(aspsp, redirectUrl, state, maxConsentValidity, psuType = "personal", psuHeaders) {
		const defaultMs = 7776e6;
		const consentMs = maxConsentValidity != null && maxConsentValidity > 0 ? Math.min(maxConsentValidity * 1e3, defaultMs) : defaultMs;
		const validUntil = new Date(Date.now() + consentMs);
		return request("POST", "/auth", {
			aspsp: {
				name: aspsp.name,
				country: aspsp.country
			},
			redirect_url: redirectUrl,
			state,
			access: {
				valid_until: validUntil.toISOString(),
				balances: true,
				transactions: true
			},
			psu_type: psuType
		}, void 0, psuHeaders);
	},
	async createSession(code) {
		return request("POST", "/sessions", { code });
	},
	async getSession(sessionId) {
		return request("GET", `/sessions/${encodeURIComponent(sessionId)}`);
	},
	async getBalances(accountUid, psuHeaders) {
		return request("GET", `/accounts/${encodeURIComponent(accountUid)}/balances`, void 0, void 0, psuHeaders);
	},
	async getTransactions(accountUid, dateFrom, dateTo, continuationKey, psuHeaders) {
		let path = `/accounts/${encodeURIComponent(accountUid)}/transactions?date_from=${encodeURIComponent(dateFrom)}&date_to=${encodeURIComponent(dateTo)}`;
		if (continuationKey) path += `&continuation_key=${encodeURIComponent(continuationKey)}`;
		return request("GET", path, void 0, void 0, psuHeaders);
	},
	async getAllTransactions(accountUid, dateFrom, dateTo, psuHeaders) {
		const allTransactions = [];
		let continuationKey;
		const maxIterations = 100;
		let iteration = 0;
		do {
			const result = await enableBankingService.getTransactions(accountUid, dateFrom, dateTo, continuationKey, psuHeaders);
			if (result.continuation_key && result.continuation_key === continuationKey) break;
			allTransactions.push(...result.transactions);
			continuationKey = result.continuation_key;
			iteration++;
		} while (continuationKey && iteration < maxIterations);
		return allTransactions;
	}
};
//#endregion
//#region src/app-enablebanking/app-enablebanking.ts
var debugSensitive$5 = createDebug("actual-sensitive:enable-banking");
var debug = createDebug("actual:enable-banking:app");
var app$7 = express();
app$7.use(requestLoggerMiddleware);
app$7.use(express.json());
function extractPsuHeaders(req) {
	const ip = req.ip && ipaddr.isValid(req.ip) ? ipaddr.process(req.ip).toString() : req.ip;
	const ua = typeof req.headers["user-agent"] === "string" ? req.headers["user-agent"] : void 0;
	if (!ip || isBlockedIp(ip)) {
		debug("Skipping PSU headers because PSU IP is local/private");
		return {};
	}
	const headers = { "Psu-Ip-Address": ip };
	if (ua) headers["Psu-User-Agent"] = ua;
	debug("Using PSU headers for public PSU IP");
	return headers;
}
var ASPSPS_WITHOUT_DATA_ACCESS_PSU_HEADERS = /* @__PURE__ */ new Set(["HypoVereinsbank"]);
function dataAccessPsuHeaders(aspspName, psuHeaders) {
	if (aspspName && ASPSPS_WITHOUT_DATA_ACCESS_PSU_HEADERS.has(aspspName)) return;
	return psuHeaders;
}
async function buildSessionResult(session, psuHeaders) {
	const accessHeaders = dataAccessPsuHeaders(session.aspsp?.name, psuHeaders);
	const accountsWithBalances = await Promise.all(session.accounts.map(async (account) => {
		const normalized = normalizeAccount(account, session.aspsp);
		let balances = [];
		try {
			balances = (await enableBankingService.getBalances(account.uid, accessHeaders)).balances.map(normalizeBalance);
		} catch (err) {
			debug("Failed to fetch account balances");
			debugSensitive$5("Failed to fetch balances for account %s: %O", account.uid, err);
		}
		const preferredBalance = balances.find((b) => b.balanceType === "CLAV") ?? balances[0];
		return {
			...normalized,
			balance: preferredBalance ? preferredBalance.balanceAmount.amount : 0,
			balances
		};
	}));
	return {
		session_id: session.session_id,
		accounts: accountsWithBalances,
		aspsp: session.aspsp
	};
}
var APP_STATE_SUFFIX = "-app";
app$7.get("/auth_callback", async (req, res) => {
	const code = typeof req.query.code === "string" ? req.query.code : void 0;
	const state = typeof req.query.state === "string" ? req.query.state : void 0;
	if (!code) {
		res.status(400).send("<html><body><p>Authorization failed: missing code.</p></body></html>");
		return;
	}
	if (!state) {
		res.status(400).send("<html><body><p>Authorization failed: missing state parameter.</p></body></html>");
		return;
	}
	try {
		const session = await enableBankingService.createSession(code);
		debug("Callback session created with %d accounts", session.accounts.length);
		debugSensitive$5("Callback session created: %s", session.session_id);
		const result = await buildSessionResult(session, extractPsuHeaders(req));
		completedAuths.set(state, result);
		setTimeout(() => completedAuths.delete(state), COMPLETED_AUTH_TTL_MS);
		const pending = pendingAuths.get(state);
		if (pending) {
			pending.resolve(result);
			cleanupPendingAuth(state);
		}
		if (state.endsWith(APP_STATE_SUFFIX)) {
			res.send(MOBILE_APP_RETURN_PAGE_HTML);
			return;
		}
		res.send("<html><body><p>Authorization successful. This window will close.</p><script>setTimeout(function(){window.close()},1000)<\/script></body></html>");
	} catch (error) {
		const errorResult = { error: error instanceof Error ? error.message : "unknown error" };
		completedAuths.set(state, errorResult);
		setTimeout(() => completedAuths.delete(state), COMPLETED_AUTH_TTL_MS);
		const pending = pendingAuths.get(state);
		if (pending) {
			pending.reject(error);
			cleanupPendingAuth(state);
		}
		debug("Callback authentication failed");
		debugSensitive$5("Callback authentication failed: %O", error);
		res.status(500).send("<html><body><p>Authorization failed. You can close this window and try again.</p></body></html>");
	}
});
app$7.use(validateSessionMiddleware);
var pendingAuths = /* @__PURE__ */ new Map();
var completedAuths = /* @__PURE__ */ new Map();
var nextWaiterId = 0;
var POLL_TIMEOUT_MS = 3e5;
var COMPLETED_AUTH_TTL_MS = 3e4;
function cleanupPendingAuth(state, waiterId) {
	const entry = pendingAuths.get(state);
	if (entry && (waiterId == null || entry.id === waiterId)) {
		clearTimeout(entry.timer);
		pendingAuths.delete(state);
	}
}
app$7.post("/status", handleError(async (req, res) => {
	const configured = enableBankingService.isConfigured();
	res.send({
		status: "ok",
		data: { configured }
	});
}));
app$7.post("/configure", handleError(async (req, res) => {
	if (!isAdmin(res.locals.user_id)) {
		res.status(403).send({
			status: "error",
			reason: "forbidden",
			details: "permission-not-found"
		});
		return;
	}
	const { secretKey } = req.body || {};
	const applicationId = typeof req.body?.applicationId === "string" ? req.body.applicationId.trim() : "";
	if (!applicationId || !secretKey) {
		res.send({
			status: "ok",
			data: {
				error_code: "INVALID_INPUT",
				error_type: "Missing applicationId or secretKey"
			}
		});
		return;
	}
	try {
		const appInfo = await enableBankingService.validateCredentials(applicationId, secretKey);
		debug("Enable Banking application validated");
		debugSensitive$5("Enable Banking application validated: %O", appInfo);
	} catch (error) {
		debug("Enable Banking configuration validation failed");
		debugSensitive$5("Enable Banking configuration validation failed: %O", error);
		res.send({
			status: "ok",
			data: {
				error_code: "CONFIGURATION_FAILED",
				error_type: error instanceof Error ? error.message : "unknown error"
			}
		});
		return;
	}
	secretsService.set(SecretName.enablebanking_applicationId, applicationId);
	secretsService.set(SecretName.enablebanking_secretKey, secretKey);
	res.send({
		status: "ok",
		data: { configured: true }
	});
}));
app$7.post("/aspsps", handleError(async (req, res) => {
	const { country } = req.body || {};
	try {
		const aspsps = await enableBankingService.getAspsps(country);
		res.send({
			status: "ok",
			data: aspsps
		});
	} catch (error) {
		res.send({
			status: "ok",
			data: { error: error instanceof Error ? error.message : "unknown error" }
		});
	}
}));
app$7.post("/start-auth", handleError(async (req, res) => {
	const { aspsp, redirectUrl, maxConsentValidity, psuType, returnToApp } = req.body || {};
	if (!aspsp || !redirectUrl) {
		res.send({
			status: "ok",
			data: {
				error_code: "INVALID_INPUT",
				error_type: "Missing aspsp or redirectUrl"
			}
		});
		return;
	}
	const state = v4() + (returnToApp === true ? APP_STATE_SUFFIX : "");
	try {
		const authResponse = await enableBankingService.startAuth(aspsp, redirectUrl, state, typeof maxConsentValidity === "number" ? maxConsentValidity : void 0, psuType === "business" ? "business" : "personal", extractPsuHeaders(req));
		res.send({
			status: "ok",
			data: {
				url: authResponse.url,
				state
			}
		});
	} catch (error) {
		res.send({
			status: "ok",
			data: { error: error instanceof Error ? error.message : "unknown error" }
		});
	}
}));
app$7.post("/complete-auth", handleError(async (req, res) => {
	const { code, state } = req.body || {};
	if (!code) {
		res.send({
			status: "ok",
			data: {
				error_code: "INVALID_INPUT",
				error_type: "Missing code"
			}
		});
		return;
	}
	try {
		const session = await enableBankingService.createSession(code);
		debug("Session created with %d accounts", session.accounts.length);
		debugSensitive$5("Session created: %s", session.session_id);
		const result = await buildSessionResult(session, extractPsuHeaders(req));
		if (state) {
			completedAuths.set(state, result);
			setTimeout(() => completedAuths.delete(state), COMPLETED_AUTH_TTL_MS);
			const pending = pendingAuths.get(state);
			if (pending) {
				pending.resolve(result);
				cleanupPendingAuth(state);
			}
		}
		res.send({
			status: "ok",
			data: result
		});
	} catch (error) {
		const errorResult = { error: error instanceof Error ? error.message : "unknown error" };
		if (state) {
			completedAuths.set(state, errorResult);
			setTimeout(() => completedAuths.delete(state), COMPLETED_AUTH_TTL_MS);
			const pending = pendingAuths.get(state);
			if (pending) {
				pending.reject(error);
				cleanupPendingAuth(state);
			}
		}
		res.send({
			status: "ok",
			data: errorResult
		});
	}
}));
app$7.post("/poll-auth", handleError(async (req, res) => {
	const { state } = req.body || {};
	if (!state) {
		res.send({
			status: "ok",
			data: {
				error_code: "INVALID_INPUT",
				error_type: "Missing state"
			}
		});
		return;
	}
	const waiterId = String(++nextWaiterId);
	let hasClientDisconnected = false;
	try {
		if (completedAuths.has(state)) {
			const result = completedAuths.get(state);
			completedAuths.delete(state);
			res.send({
				status: "ok",
				data: result
			});
			return;
		}
		const result = await new Promise((resolve, reject) => {
			const existing = pendingAuths.get(state);
			if (existing) {
				clearTimeout(existing.timer);
				existing.reject(/* @__PURE__ */ new Error("Poll superseded"));
			}
			let settled = false;
			const safeResolve = (value) => {
				if (settled) return;
				settled = true;
				resolve(value);
			};
			const safeReject = (reason) => {
				if (settled) return;
				settled = true;
				reject(reason);
			};
			const timer = setTimeout(() => {
				cleanupPendingAuth(state, waiterId);
				safeReject(/* @__PURE__ */ new Error("Polling timed out"));
			}, POLL_TIMEOUT_MS);
			pendingAuths.set(state, {
				id: waiterId,
				resolve: safeResolve,
				reject: safeReject,
				timer
			});
			res.on("close", () => {
				if (!res.writableFinished && !settled) {
					hasClientDisconnected = true;
					cleanupPendingAuth(state, waiterId);
					safeReject(/* @__PURE__ */ new Error("Client disconnected"));
				}
			});
		});
		if (hasClientDisconnected || res.destroyed || res.writableEnded) return;
		res.send({
			status: "ok",
			data: result
		});
	} catch (error) {
		cleanupPendingAuth(state, waiterId);
		if (hasClientDisconnected || res.destroyed || res.writableEnded) return;
		res.send({
			status: "ok",
			data: { error: error instanceof Error ? error.message : "unknown error" }
		});
	}
}));
app$7.post("/transactions", handleError(async (req, res) => {
	const { accountId, startDate, aspspName } = req.body || {};
	if (!accountId || !startDate) {
		res.send({
			status: "ok",
			data: {
				error_code: "INVALID_INPUT",
				error_type: "Missing accountId or startDate"
			}
		});
		return;
	}
	try {
		const dateTo = (/* @__PURE__ */ new Date()).toISOString().split("T")[0];
		const dateFrom = typeof startDate === "string" ? startDate : new Date(startDate).toISOString().split("T")[0];
		const psuHeaders = dataAccessPsuHeaders(aspspName, extractPsuHeaders(req));
		let balances = [];
		try {
			balances = (await enableBankingService.getBalances(accountId, psuHeaders)).balances.map(normalizeBalance);
		} catch (err) {
			debug("Failed to fetch account balances");
			debugSensitive$5("Failed to fetch balances for account %s: %O", accountId, err);
		}
		let startingBalance = null;
		if (balances.length > 0) startingBalance = (balances.find((b) => b.balanceType === "CLAV") ?? balances[0]).balanceAmount.amount;
		const rawTransactions = await enableBankingService.getAllTransactions(accountId, dateFrom, dateTo, psuHeaders);
		const all = [];
		const booked = [];
		const pending = [];
		for (const normalized of normalizeTransactions(rawTransactions)) {
			if (!isImportableTransaction(normalized)) {
				debugSensitive$5("Skipping unimportable transaction id=%s date=%s amount=%s", normalized.transactionId, normalized.date, normalized.transactionAmount.amount);
				continue;
			}
			all.push(normalized);
			if (normalized.booked) booked.push(normalized);
			else pending.push(normalized);
		}
		res.send({
			status: "ok",
			data: {
				transactions: {
					all,
					booked,
					pending
				},
				balances,
				startingBalance
			}
		});
	} catch (error) {
		debug("Error fetching transactions");
		debugSensitive$5("Error fetching transactions: %O", error);
		if (error instanceof EnableBankingError) {
			if (error.error_code === "INVALID_ACCESS_TOKEN") {
				res.send({
					status: "ok",
					data: {
						error_type: "ITEM_ERROR",
						error_code: "ITEM_LOGIN_REQUIRED"
					}
				});
				return;
			}
			const wireErrorType = error.error_code === "NOT_FOUND" ? "INVALID_INPUT" : error.error_code;
			res.send({
				status: "ok",
				data: {
					error_type: wireErrorType,
					error_code: error.error_code
				}
			});
			return;
		}
		res.send({
			status: "ok",
			data: {
				error_type: "INTERNAL_ERROR",
				error_code: "INTERNAL_ERROR"
			}
		});
	}
}));
//#endregion
//#region src/util/hash.ts
function sha256String(str) {
	return crypto.createHash("sha256").update(str).digest("base64");
}
//#endregion
//#region src/app-gocardless/errors.ts
var RequisitionNotLinked = class extends Error {
	details;
	constructor(params = {}) {
		super("Requisition not linked yet");
		this.details = params;
	}
};
var AccountNotLinkedToRequisition = class extends Error {
	details;
	constructor(accountId, requisitionId) {
		super("Provided account id is not linked to given requisition");
		this.details = {
			accountId,
			requisitionId
		};
	}
};
var GenericGoCardlessError = class extends Error {
	details;
	constructor(data = {}) {
		super("GoCardless returned error");
		this.details = data;
	}
};
var GoCardlessClientError = class extends Error {
	details;
	constructor(message, details) {
		super(message);
		this.details = details;
	}
};
var InvalidInputDataError = class extends GoCardlessClientError {
	constructor(response) {
		super("Invalid provided parameters", response);
	}
};
var InvalidGoCardlessTokenError = class extends GoCardlessClientError {
	constructor(response) {
		super("Token is invalid or expired", response);
	}
};
var EndUserAgreementExpiredError = class extends GoCardlessClientError {
	constructor(response) {
		super("End User Agreement (EUA) has expired", response);
	}
};
var AccessDeniedError = class extends GoCardlessClientError {
	constructor(response) {
		super("IP address access denied", response);
	}
};
var NotFoundError = class extends GoCardlessClientError {
	constructor(response) {
		super("Resource not found", response);
	}
};
var ResourceSuspended = class extends GoCardlessClientError {
	constructor(response) {
		super("Resource was suspended due to numerous errors that occurred while accessing it", response);
	}
};
var RateLimitError = class extends GoCardlessClientError {
	constructor(response) {
		super("Daily request limit set by the Institution has been exceeded", response);
	}
};
var UnknownError = class extends GoCardlessClientError {
	constructor(response) {
		super("Request to Institution returned an error", response);
	}
};
var ServiceError = class extends GoCardlessClientError {
	constructor(response) {
		super("Institution service unavailable", response);
	}
};
//#endregion
//#region src/app-gocardless/utils.ts
var printIban = (account) => {
	if (account.iban) return "(XXX " + account.iban.slice(-4) + ")";
	else return "";
};
var compareDates = (a, b) => {
	if (a == null && b == null) return 0;
	else if (a == null) return 1;
	else if (b == null) return -1;
	return +new Date(a) - +new Date(b);
};
var compareFunctions = [
	(a, b) => compareDates(a.bookingDate, b.bookingDate),
	(a, b) => compareDates(a.bookingDateTime, b.bookingDateTime),
	(a, b) => compareDates(a.valueDate, b.valueDate),
	(a, b) => compareDates(a.valueDateTime, b.valueDateTime)
];
var sortByBookingDateOrValueDate = (transactions = []) => transactions.sort((a, b) => {
	for (const sortFunction of compareFunctions) {
		const result = sortFunction(b, a);
		if (result !== 0) return result;
	}
	return 0;
});
var amountToInteger = (n) => Math.round(Number(n) * 100);
//#endregion
//#region src/util/title/lower-case.ts
var conjunctions = [
	"for",
	"and",
	"nor",
	"but",
	"or",
	"yet",
	"so"
];
var articles = [
	"a",
	"an",
	"the"
];
var prepositions = [
	"aboard",
	"about",
	"above",
	"across",
	"after",
	"against",
	"along",
	"amid",
	"among",
	"anti",
	"around",
	"as",
	"at",
	"before",
	"behind",
	"below",
	"beneath",
	"beside",
	"besides",
	"between",
	"beyond",
	"but",
	"by",
	"concerning",
	"considering",
	"despite",
	"down",
	"during",
	"except",
	"excepting",
	"excluding",
	"following",
	"for",
	"from",
	"in",
	"inside",
	"into",
	"like",
	"minus",
	"near",
	"of",
	"off",
	"on",
	"onto",
	"opposite",
	"over",
	"past",
	"per",
	"plus",
	"regarding",
	"round",
	"save",
	"since",
	"than",
	"through",
	"to",
	"toward",
	"towards",
	"under",
	"underneath",
	"unlike",
	"until",
	"up",
	"upon",
	"versus",
	"via",
	"with",
	"within",
	"without"
];
var lowerCaseSet = /* @__PURE__ */ new Set([
	...conjunctions,
	...articles,
	...prepositions
]);
//#endregion
//#region src/util/title/specials.ts
var specials = [
	"CLI",
	"API",
	"HTTP",
	"HTTPS",
	"JSX",
	"DNS",
	"URL",
	"CI",
	"CDN",
	"GitHub",
	"CSS",
	"JS",
	"JavaScript",
	"TypeScript",
	"HTML",
	"WordPress",
	"JavaScript",
	"Next.js",
	"Node.js"
];
//#endregion
//#region src/util/title/index.ts
var character = "[0-9A-Za-zªµºÀ-ÖØ-öø-ˁˆ-ˑˠ-ˤˬˮͰ-ʹͶ-ͷͺ-ͽΆΈ-ΊΌΎ-ΡΣ-ϵϷ-ҁҊ-ԣԱ-Ֆՙա-ևא-תװ-ײء-يٮ-ٯٱ-ۓەۥ-ۦۮ-ۯۺ-ۼۿܐܒ-ܯݍ-ޥޱߊ-ߪߴ-ߵߺऄ-हऽॐक़-ॡॱ-ॲॻ-ॿঅ-ঌএ-ঐও-নপ-রলশ-হঽৎড়-ঢ়য়-ৡৰ-ৱਅ-ਊਏ-ਐਓ-ਨਪ-ਰਲ-ਲ਼ਵ-ਸ਼ਸ-ਹਖ਼-ੜਫ਼ੲ-ੴઅ-ઍએ-ઑઓ-નપ-રલ-ળવ-હઽૐૠ-ૡଅ-ଌଏ-ଐଓ-ନପ-ରଲ-ଳଵ-ହଽଡ଼-ଢ଼ୟ-ୡୱஃஅ-ஊஎ-ஐஒ-கங-சஜஞ-டண-தந-பம-ஹௐఅ-ఌఎ-ఐఒ-నప-ళవ-హఽౘ-ౙౠ-ౡಅ-ಌಎ-ಐಒ-ನಪ-ಳವ-ಹಽೞೠ-ೡഅ-ഌഎ-ഐഒ-നപ-ഹഽൠ-ൡൺ-ൿඅ-ඖක-නඳ-රලව-ෆก-ะา-ำเ-ๆກ-ຂຄງ-ຈຊຍດ-ທນ-ຟມ-ຣລວສ-ຫອ-ະາ-ຳຽເ-ໄໆໜ-ໝༀཀ-ཇཉ-ཬྈ-ྋက-ဪဿၐ-ၕၚ-ၝၡၥ-ၦၮ-ၰၵ-ႁႎႠ-Ⴥა-ჺჼᄀ-ᅙᅟ-ᆢᆨ-ᇹሀ-ቈቊ-ቍቐ-ቖቘቚ-ቝበ-ኈኊ-ኍነ-ኰኲ-ኵኸ-ኾዀዂ-ዅወ-ዖዘ-ጐጒ-ጕጘ-ፚᎀ-ᎏᎠ-Ᏼᐁ-ᙬᙯ-ᙶᚁ-ᚚᚠ-ᛪᛮ-ᛰᜀ-ᜌᜎ-ᜑᜠ-ᜱᝀ-ᝑᝠ-ᝬᝮ-ᝰក-ឳៗៜᠠ-ᡷᢀ-ᢨᢪᤀ-ᤜᥐ-ᥭᥰ-ᥴᦀ-ᦩᧁ-ᧇᨀ-ᨖᬅ-ᬳᭅ-ᭋᮃ-ᮠᮮ-ᮯᰀ-ᰣᱍ-ᱏᱚ-ᱽᴀ-ᶿḀ-ἕἘ-Ἕἠ-ὅὈ-Ὅὐ-ὗὙὛὝὟ-ώᾀ-ᾴᾶ-ᾼιῂ-ῄῆ-ῌῐ-ΐῖ-Ίῠ-Ῥῲ-ῴῶ-ῼⁱⁿₐ-ₔℂℇℊ-ℓℕℙ-ℝℤΩℨK-ℭℯ-ℹℼ-ℿⅅ-ⅉⅎⅠ-ↈⰀ-Ⱞⰰ-ⱞⱠ-Ɐⱱ-ⱽⲀ-ⳤⴀ-ⴥⴰ-ⵥⵯⶀ-ⶖⶠ-ⶦⶨ-ⶮⶰ-ⶶⶸ-ⶾⷀ-ⷆⷈ-ⷎⷐ-ⷖⷘ-ⷞⸯ々-〇〡-〩〱-〵〸-〼ぁ-ゖゝ-ゟァ-ヺー-ヿㄅ-ㄭㄱ-ㆎㆠ-ㆷㇰ-ㇿ㐀䶵一鿃ꀀ-ꒌꔀ-ꘌꘐ-ꘟꘪ-ꘫꙀ-ꙟꙢ-ꙮꙿ-ꚗꜗ-ꜟꜢ-ꞈꞋ-ꞌꟻ-ꠁꠃ-ꠅꠇ-ꠊꠌ-ꠢꡀ-ꡳꢂ-ꢳꤊ-ꤥꤰ-ꥆꨀ-ꨨꩀ-ꩂꩄ-ꩋ가힣豈-鶴侮-頻並-龎ﬀ-ﬆﬓ-ﬗיִײַ-ﬨשׁ-זּטּ-לּמּנּ-סּףּ-פּצּ-ﮱﯓ-ﴽﵐ-ﶏﶒ-ﷇﷰ-ﷻﹰ-ﹴﹶ-ﻼＡ-Ｚａ-ｚｦ-ﾾￂ-ￇￊ-ￏￒ-ￗￚ-ￜ]";
var regex = new RegExp(`(?:(?:(\\s?(?:^|[.\\(\\)!?;:"-])\\s*)(${character}))|(${character}))(${character}*[’']*${character}*)`, "g");
var convertToRegExp = (specials) => specials.map((s) => [new RegExp(`\\b${s}\\b`, "gi"), s]);
function parseMatch(match) {
	const firstCharacter = match[0];
	if (/\s/.test(firstCharacter)) return match.substr(1);
	if (/[()]/.test(firstCharacter)) return null;
	return match;
}
function title(str, options = {}) {
	str = str.toLowerCase().replace(regex, (m, lead = "", forced, lower, rest) => {
		const parsedMatch = parseMatch(m);
		if (!parsedMatch) return m;
		if (!forced) {
			const fullLower = lower + rest;
			if (lowerCaseSet.has(fullLower)) return parsedMatch;
		}
		return lead + (lower || forced).toUpperCase() + rest;
	});
	const customSpecials = options.special || [];
	convertToRegExp([...specials, ...customSpecials]).forEach(([pattern, s]) => {
		str = str.replace(pattern, s);
	});
	return str;
}
//#endregion
//#region src/util/payee-name.ts
function formatPayeeIban(iban) {
	return "(" + iban.slice(0, 4) + " XXX " + iban.slice(-4) + ")";
}
var formatPayeeName = (trans) => {
	const amount = Number(trans.transactionAmount.amount);
	const nameParts = [];
	let name;
	let account;
	if (amount > 0 || Object.is(amount, 0)) {
		name = trans.debtorName;
		account = trans.debtorAccount;
	} else {
		name = trans.creditorName;
		account = trans.creditorAccount;
	}
	account = name ? account : trans.debtorAccount || trans.creditorAccount;
	name = name || trans.debtorName || trans.creditorName || trans.remittanceInformationUnstructured || (trans.remittanceInformationUnstructuredArray || []).join(", ") || trans.additionalInformation;
	if (name) nameParts.push(title(name));
	if (typeof account === "object" && account && account.iban) nameParts.push(formatPayeeIban(account.iban));
	return nameParts.join(" ");
};
//#endregion
//#region src/app-gocardless/banks/integration-bank.ts
var SORTED_BALANCE_TYPE_LIST = [
	"closingBooked",
	"expected",
	"forwardAvailable",
	"interimAvailable",
	"interimBooked",
	"nonInvoiced",
	"openingBooked"
];
var integration_bank_default = {
	institutionIds: ["IntegrationBank"],
	normalizeAccount(account) {
		return {
			account_id: account.id,
			institution: account.institution,
			mask: (account?.iban || "0000").slice(-4),
			iban: account?.iban || null,
			name: [
				account.name ?? account.displayName ?? account.product,
				printIban(account),
				account.currency
			].filter(Boolean).join(" "),
			official_name: account.product ?? `integration-${account.institution_id}`,
			type: "checking"
		};
	},
	normalizeTransaction(transaction, _booked, editedTransaction) {
		const trans = editedTransaction ?? transaction;
		const date = trans.date || transaction.bookingDate || transaction.bookingDateTime || transaction.valueDate || transaction.valueDateTime;
		if (!date) return null;
		const notes = trans.notes ?? trans.remittanceInformationUnstructured ?? trans.remittanceInformationUnstructuredArray?.join(" ") ?? "";
		transaction.remittanceInformationUnstructuredArrayString = transaction.remittanceInformationUnstructuredArray?.join(",");
		transaction.remittanceInformationStructuredArrayString = transaction.remittanceInformationStructuredArray?.join(",");
		return {
			...transaction,
			payeeName: trans.payeeName ?? formatPayeeName(trans),
			date: d.format(d.parseISO(date), "yyyy-MM-dd"),
			notes
		};
	},
	sortTransactions(transactions = []) {
		return sortByBookingDateOrValueDate(transactions);
	},
	calculateStartingBalance(sortedTransactions = [], balances = []) {
		const currentBalance = balances.filter((item) => SORTED_BALANCE_TYPE_LIST.includes(item.balanceType)).sort((a, b) => SORTED_BALANCE_TYPE_LIST.indexOf(a.balanceType) - SORTED_BALANCE_TYPE_LIST.indexOf(b.balanceType))[0];
		return sortedTransactions.reduce((total, trans) => {
			return total - amountToInteger(trans.transactionAmount.amount);
		}, amountToInteger(currentBalance?.balanceAmount.amount || 0));
	}
};
//#endregion
//#region src/app-gocardless/banks/abanca_caglesmm.ts
var abanca_caglesmm_exports = /* @__PURE__ */ __exportAll({ default: () => abanca_caglesmm_default });
var abanca_caglesmm_default = {
	...integration_bank_default,
	institutionIds: [
		"ABANCA_CAGLESMM",
		"ABANCA_CAGLPTPL",
		"ABANCA_CORP_CAGLPTPL"
	],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		editedTrans.creditorName = transaction.remittanceInformationStructured;
		editedTrans.debtorName = transaction.remittanceInformationStructured;
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
//#endregion
//#region src/app-gocardless/banks/abnamro_abnanl2a.ts
var abnamro_abnanl2a_exports = /* @__PURE__ */ __exportAll({ default: () => abnamro_abnanl2a_default });
var abnamro_abnanl2a_default = {
	...integration_bank_default,
	institutionIds: ["ABNAMRO_ABNANL2A"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		const infoArray = transaction.remittanceInformationUnstructuredArray ?? [];
		editedTrans.remittanceInformationUnstructured = infoArray.join(", ");
		const payeeName = infoArray.map((el) => el.match(/^(?:.*\*)?(.+),PAS\d+$/)).find((match) => match)?.[1];
		editedTrans.debtorName = transaction.debtorName || payeeName;
		editedTrans.creditorName = transaction.creditorName || payeeName;
		editedTrans.date = (transaction.valueDateTime ?? "").slice(0, 10);
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	},
	sortTransactions(transactions = []) {
		return transactions.sort((a, b) => +new Date(b.valueDateTime ?? "") - +new Date(a.valueDateTime ?? ""));
	},
	calculateStartingBalance(sortedTransactions = [], balances = []) {
		if (sortedTransactions.length) {
			const oldestTransaction = sortedTransactions[sortedTransactions.length - 1];
			return amountToInteger(oldestTransaction.balanceAfterTransaction?.balanceAmount.amount || 0) - amountToInteger(oldestTransaction.transactionAmount.amount);
		} else return amountToInteger(balances.find((balance) => "interimBooked" === balance.balanceType)?.balanceAmount.amount || 0);
	}
};
//#endregion
//#region src/app-gocardless/banks/alior_albpplpw.ts
var alior_albpplpw_exports = /* @__PURE__ */ __exportAll({ default: () => alior_albpplpw_default });
/**
* Alior Bank stopped returning `creditorName` on outgoing transactions in
* early July 2026. For card payments the merchant is still there, behind a
* fixed prefix, in `remittanceInformationUnstructured`:
*
*   "Transakcja kartą debetową, Example Coffee Bar"
*
* Credit card accounts send the same thing without the card type:
*
*   "Transakcja kartą, Example Coffee Bar"
*
* Without the merchant, `formatPayeeName` walks its fallback chain down to
* `debtorName`, which on an outgoing transaction is the account holder. Every
* card payment then gets booked against the account holder instead of the
* shop.
*
* Only card payments are handled here. On the remaining outgoing transactions
* (transfers, ATM withdrawals, loan instalments) the recipient is not present
* in the payload at all, so there is nothing better to fall back to.
*
* Everything after the first comma is the merchant: Alior truncates that field
* to 22 characters and appends nothing after it, so there are no further comma
* separated fields to trip over. Checked against a 90 day window of real card
* payments: none of the merchant names contained a comma or a line break, and
* `remittanceInformationUnstructuredArray` was always a single element equal to
* `remittanceInformationUnstructured`.
*/
var CARD_PAYMENT_MERCHANT = /^Transakcja kartą[^,]*,\s*(.+)$/is;
var alior_albpplpw_default = {
	...integration_bank_default,
	institutionIds: ["ALIOR_ALBPPLPW"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		if (Number(transaction.transactionAmount.amount) < 0 && !transaction.creditorName) {
			const merchant = (transaction.remittanceInformationUnstructured ?? "").match(CARD_PAYMENT_MERCHANT)?.[1].trim() ?? "";
			if (merchant) editedTrans.creditorName = merchant;
		}
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
//#endregion
//#region src/app-gocardless/banks/american_express_aesudef1.ts
var american_express_aesudef1_exports = /* @__PURE__ */ __exportAll({ default: () => american_express_aesudef1_default });
var american_express_aesudef1_default = {
	...integration_bank_default,
	institutionIds: ["AMERICAN_EXPRESS_AESUDEF1"],
	normalizeAccount(account) {
		return {
			...integration_bank_default.normalizeAccount(account),
			mask: account.iban.slice(-5),
			iban: null,
			name: [account.details, `(${account.iban.slice(-5)})`].join(" "),
			official_name: account.details ?? ""
		};
	},
	/**
	*  For AMERICAN_EXPRESS_AESUDEF1 we don't know what balance was
	*  after each transaction so we have to calculate it by getting
	*  current balance from the account and subtract all the transactions
	*
	*  As a current balance we use the non-standard `information` balance type
	*  which is the only one provided for American Express.
	*/
	calculateStartingBalance(sortedTransactions = [], balances = []) {
		const currentBalance = balances.find((balance) => "information" === balance.balanceType.toString());
		return sortedTransactions.reduce((total, trans) => {
			return total - amountToInteger(trans.transactionAmount.amount);
		}, amountToInteger(currentBalance?.balanceAmount.amount || 0));
	}
};
//#endregion
//#region src/app-gocardless/banks/bancsabadell_bsabesbbb.ts
var bancsabadell_bsabesbbb_exports = /* @__PURE__ */ __exportAll({ default: () => bancsabadell_bsabesbbb_default });
var bancsabadell_bsabesbbb_default = {
	...integration_bank_default,
	institutionIds: ["BANCSABADELL_BSABESBB"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		const amount = transaction.transactionAmount.amount;
		const isCreditorPayee = Number.parseFloat(amount) < 0;
		const payeeName = (transaction.remittanceInformationUnstructuredArray ?? []).join(" ").trim();
		editedTrans.creditorName = isCreditorPayee ? payeeName : void 0;
		editedTrans.debtorName = isCreditorPayee ? void 0 : payeeName;
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
//#endregion
//#region src/app-gocardless/banks/bank_of_ireland_b365_bofiie2d.ts
var bank_of_ireland_b365_bofiie2d_exports = /* @__PURE__ */ __exportAll({ default: () => bank_of_ireland_b365_bofiie2d_default });
var bank_of_ireland_b365_bofiie2d_default = {
	...integration_bank_default,
	institutionIds: ["BANK_OF_IRELAND_B365_BOFIIE2D"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		editedTrans.remittanceInformationUnstructured = fixupPayee(transaction.remittanceInformationUnstructured ?? "");
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
function fixupPayee(payee) {
	let fixedPayee = payee;
	fixedPayee = fixedPayee.replace(/\s+/g, " ").trim();
	fixedPayee = fixedPayee.replace(/^(POS)?(C)?[0-9]{1,2}\w{3}/, "").trim();
	fixedPayee = fixedPayee.replace(/sepa dd$/i, "").trim();
	fixedPayee = fixedPayee.replace(/^365 online/i, "").trim();
	fixedPayee = fixedPayee.replace(/^CRV\*/, "").trim();
	return fixedPayee;
}
//#endregion
//#region src/app-gocardless/banks/bankinter_bkbkesmm.ts
var bankinter_bkbkesmm_exports = /* @__PURE__ */ __exportAll({ default: () => bankinter_bkbkesmm_default });
var bankinter_bkbkesmm_default = {
	...integration_bank_default,
	institutionIds: ["BANKINTER_BKBKESMM"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		editedTrans.remittanceInformationUnstructured = (transaction.remittanceInformationUnstructured ?? "").replaceAll(/\/Txt\/(\w\|)?/gi, "").replaceAll(";", " ");
		editedTrans.debtorName = transaction.debtorName?.replaceAll(";", " ");
		editedTrans.creditorName = transaction.creditorName?.replaceAll(";", " ") ?? editedTrans.remittanceInformationUnstructured;
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
//#endregion
//#region src/app-gocardless/banks/belfius_gkccbebb.ts
var belfius_gkccbebb_exports = /* @__PURE__ */ __exportAll({ default: () => belfius_gkccbebb_default });
var belfius_gkccbebb_default = {
	...integration_bank_default,
	institutionIds: ["BELFIUS_GKCCBEBB"],
	normalizeTransaction(transaction, booked) {
		transaction.transactionId = transaction.internalTransactionId;
		return integration_bank_default.normalizeTransaction(transaction, booked);
	}
};
//#endregion
//#region src/app-gocardless/banks/berliner_sparkasse_beladebexxx.ts
var berliner_sparkasse_beladebexxx_exports = /* @__PURE__ */ __exportAll({ default: () => berliner_sparkasse_beladebexxx_default });
var berliner_sparkasse_beladebexxx_default = {
	...integration_bank_default,
	institutionIds: ["BERLINER_SPARKASSE_BELADEBEXXX"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		let remittanceInformationUnstructured;
		if (transaction.remittanceInformationUnstructured) remittanceInformationUnstructured = transaction.remittanceInformationUnstructured;
		else if (transaction.remittanceInformationStructured) remittanceInformationUnstructured = transaction.remittanceInformationStructured;
		else if ((transaction.remittanceInformationStructuredArray?.length ?? 0) > 0) remittanceInformationUnstructured = transaction.remittanceInformationStructuredArray?.join(" ");
		if (transaction.additionalInformation) remittanceInformationUnstructured += " " + transaction.additionalInformation;
		editedTrans.creditorName = transaction.ultimateCreditor || transaction.creditorName || transaction.debtorName;
		editedTrans.remittanceInformationUnstructured = remittanceInformationUnstructured;
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	},
	/**
	*  For SANDBOXFINANCE_SFIN0000 we don't know what balance was
	*  after each transaction so we have to calculate it by getting
	*  current balance from the account and subtract all the transactions
	*
	*  As a current balance we use `interimBooked` balance type because
	*  it includes transaction placed during current day
	*/
	calculateStartingBalance(sortedTransactions = [], balances = []) {
		const currentBalance = balances.find((balance) => "interimAvailable" === balance.balanceType);
		return sortedTransactions.reduce((total, trans) => {
			return total - amountToInteger(trans.transactionAmount.amount);
		}, amountToInteger(currentBalance?.balanceAmount.amount || 0));
	}
};
//#endregion
//#region src/app-gocardless/banks/bnp_be_gebabebb.ts
var bnp_be_gebabebb_exports = /* @__PURE__ */ __exportAll({ default: () => bnp_be_gebabebb_default });
var bnp_be_gebabebb_default = {
	...integration_bank_default,
	institutionIds: [
		"FINTRO_BE_GEBABEBB",
		"HELLO_BE_GEBABEBB",
		"BNP_BE_GEBABEBB"
	],
	/** BNP_BE_GEBABEBB provides a lot of useful information via the 'additionalField'
	*  There does not seem to be a specification of this field, but the following information is contained in its subfields:
	*  - for pending transactions: the 'atmPosName'
	*  - for booked transactions: the 'narrative'.
	*  This narrative subfield is most useful as it contains information required to identify the transaction,
	*  especially in case of debit card or instant payment transactions.
	*  Do note that the narrative subfield ALSO contains the remittance information if any.
	*  The goal of the  normalization is to place any relevant information of the additionalInformation
	*  field in the remittanceInformationUnstructuredArray field.
	*/
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		let creditorName = transaction.creditorName;
		if (transaction.additionalInformation) {
			const additionalInformationObject = {};
			const matches = transaction.additionalInformation.matchAll(/(, )?([^:]+): ((\[.*?\])|([^,]*))/g);
			if (matches) {
				let creditorNameFromNarrative;
				for (const match of matches) {
					const key = match[2].trim();
					let value = (match[4] || match[5]).trim();
					if (key === "narrative") {
						const first_value = value.matchAll(/'(.+?)'/g)?.next().value;
						creditorNameFromNarrative = first_value ? first_value[1].trim() : void 0;
					}
					value = value.replace(/[[\]',]/g, "");
					additionalInformationObject[key] = value;
				}
				editedTrans.remittanceInformationUnstructuredArray = [
					...transaction.remittanceInformationUnstructuredArray ?? [],
					additionalInformationObject?.atmPosName,
					additionalInformationObject?.narrative
				].filter(Boolean);
				creditorName = creditorName ?? additionalInformationObject?.atmPosName ?? creditorNameFromNarrative ?? null;
			}
		}
		editedTrans.creditorName = creditorName;
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
//#endregion
//#region src/app-gocardless/banks/boursobank_bousfrppxxx.ts
var boursobank_bousfrppxxx_exports = /* @__PURE__ */ __exportAll({ default: () => boursobank_bousfrppxxx_default });
var regexCard = /^CARTE (?<date>\d{2}\/\d{2}\/\d{2}) (?<payeeName>.+?)( \d+)?( CB\*\d{4})?$/;
var regexAtmWithdrawal = /^RETRAIT DAB (?<date>\d{2}\/\d{2}\/\d{2}) (?<locationName>.+?) CB\*\d{4,}/;
var regexTransfer = /^VIR /;
var regexInstantTransfer = /^VIR INST /;
var regexSepa = /^(PRLV|VIR) SEPA /;
var regexLoan = /^ECH PRET:/;
var regexCreditNote = /^AVOIR (?<date>\d{2}\/\d{2}\/\d{2}) (?<payeeName>.+?) CB\*\d{4,}/;
var boursobank_bousfrppxxx_default = {
	...integration_bank_default,
	institutionIds: ["BOURSORAMA_BOUSFRPP"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		editedTrans.remittanceInformationUnstructuredArray = (transaction.remittanceInformationUnstructuredArray ?? []).map((line) => line.replace(/\\.+/g, "")).filter((line) => line.startsWith("Réf : ") === false);
		const infoArray = editedTrans.remittanceInformationUnstructuredArray;
		let match;
		if (match = infoArray.find((line) => regexCard.test(line))) {
			const cardMatch = match.match(regexCard);
			editedTrans.payeeName = title(cardMatch?.groups?.payeeName ?? "");
			editedTrans.notes = `Carte ${cardMatch?.groups?.date}`;
			if (infoArray.length > 1) editedTrans.notes += " " + infoArray.filter((l) => l !== match).join(" ");
		} else if (match = infoArray.find((line) => regexLoan.test(line))) {
			editedTrans.payeeName = "Prêt bancaire";
			editedTrans.notes = match;
		} else if (match = infoArray.find((line) => regexAtmWithdrawal.test(line))) {
			const atmMatch = match.match(regexAtmWithdrawal);
			editedTrans.payeeName = "Retrait DAB";
			editedTrans.notes = `Retrait ${atmMatch?.groups?.date} ${atmMatch?.groups?.locationName}`;
			if (infoArray.length > 1) editedTrans.notes += " " + infoArray.filter((l) => l !== match).join(" ");
		} else if (match = infoArray.find((line) => regexCreditNote.test(line))) {
			const creditMatch = match.match(regexCreditNote);
			editedTrans.payeeName = title(creditMatch?.groups?.payeeName ?? "");
			editedTrans.notes = `Avoir ${creditMatch?.groups?.date}`;
			if (infoArray.length > 1) editedTrans.notes += " " + infoArray.filter((l) => l !== match).join(" ");
		} else if (match = infoArray.find((line) => regexInstantTransfer.test(line))) {
			editedTrans.payeeName = title(match.replace(regexInstantTransfer, ""));
			editedTrans.notes = infoArray.filter((l) => l !== match).join(" ");
		} else if (match = infoArray.find((line) => regexSepa.test(line))) {
			editedTrans.payeeName = title(match.replace(regexSepa, ""));
			editedTrans.notes = infoArray.filter((l) => l !== match).join(" ");
		} else if (match = infoArray.find((line) => regexTransfer.test(line))) {
			editedTrans.payeeName = title(infoArray.filter((l) => l !== match).join(" "));
			editedTrans.notes = match.replace(regexTransfer, "");
		} else {
			editedTrans.payeeName = title(infoArray[0].replace(/ \d+$/, ""));
			editedTrans.notes = infoArray.slice(1).join(" ");
		}
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
//#endregion
//#region src/app-gocardless/banks/bper_retail_bpmoit22.ts
var bper_retail_bpmoit22_exports = /* @__PURE__ */ __exportAll({ default: () => BperRetailBank });
var CARD_PAYMENT_PREFIX = "PAGAMENTO SU CIRCUITO INTERNAZIONALE";
var CARD_PAYMENT_SUFFIX = "Operazione carta";
var BONIFICO_PREFIX = "BONIFICO";
var BONIFICO_ESTERI_PREFIX = "BONIFICI ESTERI";
var SDD_PREFIX = "ADDEBITO SDD";
var BOLLETTINO_MARKER = "CREDITORE:";
var BONIFICO_ORIGINATOR_REGEX = /o\/c:\s*([A-Z0-9\s.'/&-]+?)(?:ABI|BIC|IBAN|a favore di|Num|EUR|$)/i;
var SDD_PAYEE_REGEX = /ADDEBITO SDD\s+([A-Z0-9\s.'/&-]+?)(?:N:|ID:|$)/i;
var BOLLETTINO_PAYEE_REGEX = /CREDITORE:\s*([A-Z0-9\s.'/&-]+)/i;
function parseCardPayee(description) {
	const [beforeSuffix] = description.split(CARD_PAYMENT_SUFFIX);
	return beforeSuffix.replace(CARD_PAYMENT_PREFIX, "").trim();
}
function parseBonificoOriginator(description) {
	const match = description.match(BONIFICO_ORIGINATOR_REGEX);
	return match ? match[1].trim() : "";
}
function parseSddPayee(description) {
	const match = description.match(SDD_PAYEE_REGEX);
	return match ? match[1].trim() : "";
}
function parseBollettinoPayee(description) {
	const match = description.match(BOLLETTINO_PAYEE_REGEX);
	return match ? match[1].trim() : "";
}
function setPayee(editedTransaction, payee) {
	if (!payee) return;
	editedTransaction.creditorName = payee;
	editedTransaction.debtorName = payee;
}
var BperRetailBank = {
	...integration_bank_default,
	institutionIds: ["BPER_RETAIL_BPMOIT22"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		const description = (transaction.remittanceInformationUnstructured || "").trim();
		if (description) editedTrans.remittanceInformationUnstructured = description;
		let payee = "";
		if (description.startsWith(CARD_PAYMENT_PREFIX)) payee = parseCardPayee(description);
		else if (description.startsWith(BONIFICO_PREFIX) || description.startsWith(BONIFICO_ESTERI_PREFIX)) payee = parseBonificoOriginator(description);
		else if (description.startsWith(SDD_PREFIX)) payee = parseSddPayee(description);
		else if (description.includes(BOLLETTINO_MARKER)) payee = parseBollettinoPayee(description);
		setPayee(editedTrans, payee);
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
//#endregion
//#region src/app-gocardless/banks/util/extract-payeeName-from-remittanceInfo.ts
/**
* Extracts the payee name from the unstructured remittance information string based on pattern detection.
*
* This function scans the `remittanceInformationUnstructured` string for the presence of
* any of the specified patterns and removes the substring from the position of the last
* occurrence of the most relevant pattern. If no patterns are found, it returns the original string.
*
* @param remittanceInformationUnstructured - The unstructured remittance information from which to extract the payee name.
* @param patterns - An array of patterns to look for within the remittance information.
*                   These patterns are used to identify and remove unwanted parts of the remittance information.
* @returns The extracted payee name, cleaned of any matched patterns, or the original
*          remittance information if no patterns are found.
*
* @example
* const remittanceInfo = 'John Doe Paiement Maestro par Carte de débit CBC 05-09-2024 à 15.43 heures 6703 19XX XXXX X...';
* const patterns = ['Paiement', 'Domiciliation', 'Transfert', 'Ordre permanent'];
* const payeeName = extractPayeeNameFromRemittanceInfo(remittanceInfo, patterns); // --> 'John Doe'
*/
function extractPayeeNameFromRemittanceInfo(remittanceInformationUnstructured, patterns) {
	if (!remittanceInformationUnstructured || !patterns.length) return remittanceInformationUnstructured;
	const indexForRemoval = patterns.reduce((maxIndex, pattern) => {
		const index = remittanceInformationUnstructured.lastIndexOf(pattern);
		return index > maxIndex ? index : maxIndex;
	}, -1);
	return indexForRemoval > -1 ? remittanceInformationUnstructured.substring(0, indexForRemoval).trim() : remittanceInformationUnstructured;
}
//#endregion
//#region src/app-gocardless/banks/cbc_cregbebb.ts
var cbc_cregbebb_exports = /* @__PURE__ */ __exportAll({ default: () => cbc_cregbebb_default });
var cbc_cregbebb_default = {
	...integration_bank_default,
	institutionIds: ["CBC_CREGBEBB"],
	/**
	* For negative amounts, the only payee information we have is returned in
	* remittanceInformationUnstructured.
	*/
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		if (Number(transaction.transactionAmount.amount) > 0) editedTrans.payeeName = transaction.debtorName || transaction.remittanceInformationUnstructured || "undefined";
		else editedTrans.payeeName = transaction.creditorName || extractPayeeNameFromRemittanceInfo(transaction.remittanceInformationUnstructured ?? "", [
			"Paiement",
			"Domiciliation",
			"Transfert",
			"Ordre permanent"
		]) || "undefined";
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
//#endregion
//#region src/app-gocardless/banks/cetelem_cetmptp1xxx.ts
var cetelem_cetmptp1xxx_exports = /* @__PURE__ */ __exportAll({ default: () => cetelem_cetmptp1xxx_default });
var cetelem_cetmptp1xxx_default = {
	...integration_bank_default,
	institutionIds: ["CETELEM_CETMPTP1XXX"],
	/**
	* Sign of transaction amount needs to be flipped for Cetelem Black credit cards
	*/
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		transaction.transactionAmount = {
			...transaction.transactionAmount,
			amount: (-parseFloat(transaction.transactionAmount.amount)).toString()
		};
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
//#endregion
//#region src/app-gocardless/banks/util/escape-regexp.ts
function escapeRegExp(string) {
	return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
//#endregion
//#region src/app-gocardless/banks/commerzbank_cobadeff.ts
var commerzbank_cobadeff_exports = /* @__PURE__ */ __exportAll({ default: () => commerzbank_cobadeff_default });
var commerzbank_cobadeff_default = {
	...integration_bank_default,
	institutionIds: ["COMMERZBANK_COBADEFF"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		editedTrans.remittanceInformationUnstructured = (transaction.remittanceInformationUnstructuredArray ?? []).join(" ");
		[
			"End-to-End-Ref.:",
			"Mandatsref:",
			"Gläubiger-ID:",
			"SEPA-BASISLASTSCHRIFT",
			"Kartenzahlung",
			"Dauerauftrag"
		].forEach((keyword) => {
			editedTrans.remittanceInformationUnstructured = (editedTrans.remittanceInformationUnstructured ?? "").replace(RegExp(keyword.split("").join("\\s*"), "gi"), ", " + keyword + " ");
		});
		const payeeTokens = (transaction.creditorName || transaction.debtorName || "").split(/[\s/]+/).filter(Boolean).map(escapeRegExp);
		let notes = editedTrans.remittanceInformationUnstructured.replace(/\s*(,)?\s+/g, "$1 ");
		if (payeeTokens.length > 0) notes = notes.replace(new RegExp(payeeTokens.join("[\\s/]+"), "gi"), " ");
		editedTrans.remittanceInformationUnstructured = notes.replace(", End-to-End-Ref.: NOTPROVIDED", "").trim();
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
//#endregion
//#region src/app-gocardless/banks/danskebank_privat.ts
var danskebank_privat_exports = /* @__PURE__ */ __exportAll({ default: () => danskebank_privat_default });
var danskebank_privat_default = {
	...integration_bank_default,
	institutionIds: ["DANSKEBANK_DABADKKK", "DANSKEBANK_DABANO22"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		/**
		* Danske Bank appends the EndToEndID: NOTPROVIDED to
		* remittanceInformationUnstructured, cluttering the data.
		*
		* We clean thais up by removing any instances of this string from all transactions.
		*
		*/
		editedTrans.remittanceInformationUnstructured = (transaction.remittanceInformationUnstructured ?? "").replace("\nEndToEndID: NOTPROVIDED", "");
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	},
	calculateStartingBalance(sortedTransactions = [], balances = []) {
		const currentBalance = balances.find((balance) => balance.balanceType === "interimAvailable");
		return sortedTransactions.reduce((total, trans) => {
			return total - amountToInteger(trans.transactionAmount.amount);
		}, amountToInteger(currentBalance?.balanceAmount.amount || 0));
	}
};
//#endregion
//#region src/app-gocardless/banks/direkt_heladef1822.ts
var direkt_heladef1822_exports = /* @__PURE__ */ __exportAll({ default: () => direkt_heladef1822_default });
var direkt_heladef1822_default = {
	...integration_bank_default,
	institutionIds: ["DIREKT_HELADEF1822"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		editedTrans.remittanceInformationUnstructured = transaction.remittanceInformationUnstructured ?? transaction.remittanceInformationStructured;
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
//#endregion
//#region src/app-gocardless/banks/easybank_bawaatww.ts
var easybank_bawaatww_exports = /* @__PURE__ */ __exportAll({ default: () => easybank_bawaatww_default });
var easybank_bawaatww_default = {
	...integration_bank_default,
	institutionIds: ["EASYBANK_BAWAATWW"],
	sortTransactions: (transactions = []) => transactions.sort((a, b) => {
		const diff = +new Date(b.valueDate || b.bookingDate || "") - +new Date(a.valueDate || a.bookingDate || "");
		if (diff !== 0) return diff;
		return parseInt(b.transactionId ?? "") - parseInt(a.transactionId ?? "");
	}),
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		let payeeName = formatPayeeName(transaction);
		const creditorAccount = typeof transaction.creditorAccount === "string" ? transaction.creditorAccount : transaction.creditorAccount?.iban;
		const hasCreditor = Boolean(transaction.creditorName || creditorAccount);
		const isInvalidFallback = Number(transaction.transactionAmount.amount) < 0 && !hasCreditor;
		if (!payeeName || isInvalidFallback) payeeName = extractPayeeName$1(transaction);
		editedTrans.payeeName = payeeName;
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
function extractPayeeName$1(transaction) {
	const structured = transaction.remittanceInformationStructured ?? "";
	const matches = structured.match(/\d{2}\.\d{2}\. \d{2}:\d{2}(.*)\\\\/);
	if (matches && matches.length > 1 && matches[1]) return title(matches[1]);
	else return structured;
}
//#endregion
//#region src/app-gocardless/banks/entercard_swednokk.ts
var entercard_swednokk_exports = /* @__PURE__ */ __exportAll({ default: () => entercard_swednokk_default });
var entercard_swednokk_default = {
	...integration_bank_default,
	institutionIds: ["ENTERCARD_SWEDNOKK"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		const remittanceInformationUnstructured = transaction.remittanceInformationUnstructured ?? "";
		if (remittanceInformationUnstructured.startsWith("billingAmount: ")) transaction.transactionAmount = {
			amount: remittanceInformationUnstructured.substring(15),
			currency: "SEK"
		};
		editedTrans.date = transaction.valueDate;
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	},
	calculateStartingBalance(sortedTransactions = [], balances = []) {
		return sortedTransactions.reduce((total, trans) => {
			return total - amountToInteger(trans.transactionAmount.amount);
		}, amountToInteger(balances[0]?.balanceAmount.amount || 0));
	}
};
//#endregion
//#region src/app-gocardless/banks/fineco_febiitm2xxx.ts
var fineco_febiitm2xxx_exports = /* @__PURE__ */ __exportAll({ default: () => fineco_febiitm2xxx_default });
var fineco_febiitm2xxx_default = {
	...integration_bank_default,
	institutionIds: ["FINECO_FEBIITM2XXX"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		if (editedTrans.proprietaryBankTransactionCode?.startsWith("W43")) editedTrans.payeeName = extractPayeeNameFromRemittanceInfo(transaction.remittanceInformationUnstructured ?? "", ["Carta"]);
		if (editedTrans.proprietaryBankTransactionCode?.startsWith("043")) {
			editedTrans.payeeName = extractPayeeNameFromRemittanceInfo(transaction.remittanceInformationUnstructured ?? "", ["Carta"]);
			const prefix_index = editedTrans.payeeName?.indexOf("presso:");
			if (prefix_index !== -1) editedTrans.payeeName = editedTrans.payeeName?.slice(prefix_index + 7);
		}
		editedTrans.payeeName = editedTrans.payeeName?.trim();
		editedTrans.notes = transaction.remittanceInformationStructured ?? transaction.remittanceInformationUnstructured;
		editedTrans.date = transaction.valueDate || transaction.bookingDate;
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
//#endregion
//#region src/app-gocardless/banks/fortuneo_ftnofrp1xxx.ts
var fortuneo_ftnofrp1xxx_exports = /* @__PURE__ */ __exportAll({ default: () => fortuneo_ftnofrp1xxx_default });
var fortuneo_ftnofrp1xxx_default = {
	...integration_bank_default,
	institutionIds: ["FORTUNEO_FTNOFRP1XXX"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		const keywordsToRemove = [
			"VIR INST",
			"VIR",
			"PRLV",
			"ANN CARTE",
			"CARTE \\d{2}\\/\\d{2}"
		];
		const details = (transaction.remittanceInformationUnstructuredArray ?? []).join(" ");
		const amount = transaction.transactionAmount.amount;
		const regex = new RegExp(keywordsToRemove.join("|"), "g");
		const payeeName = details.replace(regex, "").trim();
		const isCreditorPayee = parseFloat(amount) < 0;
		editedTrans.creditorName = isCreditorPayee ? payeeName : void 0;
		editedTrans.debtorName = isCreditorPayee ? void 0 : payeeName;
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
//#endregion
//#region src/app-gocardless/banks/hype_hyeeit22.ts
var hype_hyeeit22_exports = /* @__PURE__ */ __exportAll({ default: () => hype_hyeeit22_default });
var hype_hyeeit22_default = {
	...integration_bank_default,
	institutionIds: ["HYPE_HYEEIT22"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		/** Online card payments - identified by "crd" transaction code
		*  always start with PAGAMENTO PRESSO + <payee name>
		*/
		if (transaction.proprietaryBankTransactionCode === "crd") editedTrans.debtorName = transaction.remittanceInformationUnstructured?.slice(17);
		/**
		* In-app money transfers (p2p) and bank transfers (bon) have remittance info structure like
		* DENARO (INVIATO/RICEVUTO) (A/DA) {payee_name} - {payment_info} (p2p)
		* HAI (INVIATO/RICEVUTO) UN BONIFICO (A/DA) {payee_name} - {payment_info} (bon)
		*/
		if (transaction.proprietaryBankTransactionCode === "p2p" || transaction.proprietaryBankTransactionCode === "bon") {
			const remittance = transaction.remittanceInformationUnstructured ?? "";
			const idx = remittance.indexOf(" - ");
			editedTrans.remittanceInformationUnstructured = idx === -1 ? remittance : remittance.slice(idx + 3).trim();
		}
		/**
		* CONVERT ESCAPED UNICODE TO CODEPOINTS
		* p2p payments allow user to write arbitrary unicode strings as messages
		* gocardless reports unicode codepoints as \Uxxxx
		* so it groups them in 4bytes bundles
		* the code below assumes this is always the case
		*/
		if (transaction.proprietaryBankTransactionCode === "p2p") {
			let str = transaction.remittanceInformationUnstructured ?? "";
			let idx = str.indexOf("\\U");
			let start_idx = idx;
			let codepoints = [];
			while (idx !== -1) {
				codepoints.push(parseInt(str.slice(idx + 2, idx + 6), 16));
				const next_idx = str.indexOf("\\U", idx + 6);
				if (next_idx === idx + 6) {
					idx = next_idx;
					continue;
				}
				str = str.slice(0, start_idx) + String.fromCodePoint(...codepoints) + str.slice(idx + 6);
				codepoints = [];
				idx = str.indexOf("\\U");
				start_idx = idx;
			}
			editedTrans.remittanceInformationUnstructured = str;
		}
		editedTrans.date = transaction.valueDate || transaction.bookingDate;
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
//#endregion
//#region src/app-gocardless/banks/ing_ingbrobu.ts
var ing_ingbrobu_exports = /* @__PURE__ */ __exportAll({ default: () => ing_ingbrobu_default });
var ing_ingbrobu_default = {
	...integration_bank_default,
	institutionIds: ["ING_INGBROBU"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		if (transaction.transactionId === "NOTPROVIDED") {
			if (transaction.proprietaryBankTransactionCode && !transaction.remittanceInformationUnstructured) editedTrans.remittanceInformationUnstructured = transaction.proprietaryBankTransactionCode;
			if (booked) {
				transaction.transactionId = transaction.internalTransactionId;
				if (transaction.remittanceInformationUnstructured && transaction.remittanceInformationUnstructured.toLowerCase().includes("card no:")) editedTrans.creditorName = transaction.remittanceInformationUnstructured.split(",")[0];
				else editedTrans.creditorName = transaction.remittanceInformationUnstructured;
			} else {
				transaction.transactionId = void 0;
				if (transaction.remittanceInformationUnstructured && transaction.remittanceInformationUnstructured.toLowerCase().includes("card no:")) editedTrans.creditorName = transaction.remittanceInformationUnstructured.replace(/x{4}/g, "Xxxx ");
				else editedTrans.creditorName = transaction.remittanceInformationUnstructured;
				editedTrans.remittanceInformationUnstructured = void 0;
			}
		}
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
//#endregion
//#region src/app-gocardless/banks/ing_ingddeff.ts
var ing_ingddeff_exports = /* @__PURE__ */ __exportAll({ default: () => ing_ingddeff_default });
var ing_ingddeff_default = {
	...integration_bank_default,
	institutionIds: ["ING_INGDDEFF"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		const remittanceInformationMatch = /remittanceinformation:(.*)$/.exec(transaction.remittanceInformationUnstructured ?? "");
		editedTrans.remittanceInformationUnstructured = remittanceInformationMatch ? remittanceInformationMatch[1] : transaction.remittanceInformationUnstructured;
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	},
	sortTransactions(transactions = []) {
		return transactions.sort((a, b) => {
			const diff = +new Date(b.valueDate || b.bookingDate || "") - +new Date(a.valueDate || a.bookingDate || "");
			if (diff) return diff;
			const idA = parseInt(a.transactionId ?? "");
			const idB = parseInt(b.transactionId ?? "");
			if (!isNaN(idA) && !isNaN(idB)) return idB - idA;
			return 0;
		});
	},
	calculateStartingBalance(sortedTransactions = [], balances = []) {
		const currentBalance = balances.find((balance) => "interimBooked" === balance.balanceType);
		return sortedTransactions.reduce((total, trans) => {
			return total - amountToInteger(trans.transactionAmount.amount);
		}, amountToInteger(currentBalance?.balanceAmount.amount || 0));
	}
};
//#endregion
//#region src/app-gocardless/banks/ing_pl_ingbplpw.ts
var ing_pl_ingbplpw_exports = /* @__PURE__ */ __exportAll({ default: () => ing_pl_ingbplpw_default });
var ing_pl_ingbplpw_default = {
	...integration_bank_default,
	institutionIds: ["ING_PL_INGBPLPW"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		editedTrans.date = transaction.valueDate;
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	},
	sortTransactions(transactions = []) {
		return transactions.sort((a, b) => {
			return Number((b.transactionId ?? "").substr(2)) - Number((a.transactionId ?? "").substr(2));
		});
	},
	calculateStartingBalance(sortedTransactions = [], balances = []) {
		if (sortedTransactions.length) {
			const oldestTransaction = sortedTransactions[sortedTransactions.length - 1];
			return amountToInteger(oldestTransaction.balanceAfterTransaction?.balanceAmount.amount || 0) - amountToInteger(oldestTransaction.transactionAmount.amount);
		} else return amountToInteger(balances.find((balance) => "interimBooked" === balance.balanceType)?.balanceAmount.amount || 0);
	}
};
//#endregion
//#region src/app-gocardless/banks/isybank_itbbitmm.ts
var isybank_itbbitmm_exports = /* @__PURE__ */ __exportAll({ default: () => isybank_itbbitmm_default });
var isybank_itbbitmm_default = {
	...integration_bank_default,
	institutionIds: ["ISYBANK_ITBBITMM"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		editedTrans.date = transaction.valueDate ?? transaction.bookingDate;
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
//#endregion
//#region src/app-gocardless/banks/kbc_kredbebb.ts
var kbc_kredbebb_exports = /* @__PURE__ */ __exportAll({ default: () => kbc_kredbebb_default });
var kbc_kredbebb_default = {
	...integration_bank_default,
	institutionIds: ["KBC_KREDBEBB", "KBC_BRUSSELS_KREDBEBB"],
	/**
	* For negative amounts, the only payee information we have is returned in
	* remittanceInformationUnstructured.
	*/
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		if (Number(transaction.transactionAmount.amount) > 0) editedTrans.payeeName = transaction.debtorName || transaction.remittanceInformationUnstructured || "undefined";
		else editedTrans.payeeName = transaction.creditorName || extractPayeeNameFromRemittanceInfo(transaction.remittanceInformationUnstructured ?? "", [
			"Betaling met",
			"Domiciliëring",
			"Overschrijving"
		]);
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
//#endregion
//#region src/app-gocardless/banks/lhv_lhvbee22.ts
var lhv_lhvbee22_exports = /* @__PURE__ */ __exportAll({ default: () => lhv_lhvbee22_default });
var lhv_lhvbee22_default = {
	...integration_bank_default,
	institutionIds: ["LHV_LHVBEE22"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		const cardTxMatch = /^\(\.\.(\d{4})\) (\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}) (.+)$/g.exec(transaction?.remittanceInformationUnstructured ?? "");
		if (cardTxMatch) {
			const extractedDate = d.parse(cardTxMatch[2], "yyyy-MM-dd", /* @__PURE__ */ new Date());
			editedTrans.payeeName = cardTxMatch[4].split("\\")[0].trim();
			if (booked && d.isValid(extractedDate)) editedTrans.date = d.format(extractedDate, "yyyy-MM-dd");
		}
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
//#endregion
//#region src/app-gocardless/banks/mbank_retail_brexplpw.ts
var mbank_retail_brexplpw_exports = /* @__PURE__ */ __exportAll({ default: () => mbank_retail_brexplpw_default });
var mbank_retail_brexplpw_default = {
	...integration_bank_default,
	institutionIds: ["MBANK_RETAIL_BREXPLPW"],
	/**
	* When requesting transaction details for MBANK_RETAIL_BREXPLPW
	* using gocardless API, it seems that bookingDate and valueDate are swapped.
	* valueDate will always come before bookingDate, so as a simple fix,
	* I have overwritten integration-bank.normalizeTransaction() here,
	* swapped dates back (by giving valueDate higher priority) and
	* called parent method with edited transaction as argument
	*/
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		editedTrans.date = transaction.valueDate || transaction.valueDateTime || transaction.bookingDate || transaction.bookingDateTime;
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	},
	sortTransactions(transactions = []) {
		return transactions.sort((a, b) => Number(b.transactionId) - Number(a.transactionId));
	},
	/**
	*  For MBANK_RETAIL_BREXPLPW we don't know what balance was
	*  after each transaction so we have to calculate it by getting
	*  current balance from the account and subtract all the transactions
	*
	*  As a current balance we use `interimBooked` balance type because
	*  it includes transaction placed during current day
	*/
	calculateStartingBalance(sortedTransactions = [], balances = []) {
		const currentBalance = balances.find((balance) => "interimBooked" === balance.balanceType);
		return sortedTransactions.reduce((total, trans) => {
			return total - amountToInteger(trans.transactionAmount.amount);
		}, amountToInteger(currentBalance?.balanceAmount.amount || 0));
	}
};
//#endregion
//#region src/app-gocardless/banks/nationwide_naiagb21.ts
var nationwide_naiagb21_exports = /* @__PURE__ */ __exportAll({ default: () => nationwide_naiagb21_default });
var nationwide_naiagb21_default = {
	...integration_bank_default,
	institutionIds: ["NATIONWIDE_NAIAGB21"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		if (!booked) editedTrans.date = new Date(Math.min(new Date(transaction.bookingDate ?? "").getTime(), (/* @__PURE__ */ new Date()).getTime())).toISOString().slice(0, 10);
		if (transaction.transactionId?.match(/^00(DEB|CRED)IT.+$/) || ![40, 32].includes(transaction.transactionId?.length ?? -1)) transaction.transactionId = void 0;
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
//#endregion
//#region src/app-gocardless/banks/nbg_ethngraaxxx.ts
var nbg_ethngraaxxx_exports = /* @__PURE__ */ __exportAll({ default: () => nbg_ethngraaxxx_default });
var nbg_ethngraaxxx_default = {
	...integration_bank_default,
	institutionIds: ["NBG_ETHNGRAAXXX"],
	/**
	* Fixes for the pending transactions:
	* - Corrects amount to negative (nbg erroneously omits the minus sign in pending transactions)
	* - Removes prefix 'ΑΓΟΡΑ' from remittance information to align with the booked transaction (necessary for fuzzy matching to work)
	*/
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		if (!transaction.transactionId && (transaction.remittanceInformationUnstructured ?? "").startsWith("ΑΓΟΡΑ ")) {
			transaction.transactionAmount = {
				amount: "-" + transaction.transactionAmount.amount,
				currency: transaction.transactionAmount.currency
			};
			editedTrans.remittanceInformationUnstructured = (transaction.remittanceInformationUnstructured ?? "").substring(6);
		}
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	},
	/**
	*  For NBG_ETHNGRAAXXX we don't know what balance was
	*  after each transaction so we have to calculate it by getting
	*  current balance from the account and subtract all the transactions
	*
	*  As a current balance we use `interimBooked` balance type because
	*  it includes transaction placed during current day
	*/
	calculateStartingBalance(sortedTransactions = [], balances = []) {
		const currentBalance = balances.find((balance) => "interimAvailable" === balance.balanceType);
		return sortedTransactions.reduce((total, trans) => {
			return total - amountToInteger(trans.transactionAmount.amount);
		}, amountToInteger(currentBalance?.balanceAmount.amount || 0));
	}
};
//#endregion
//#region src/app-gocardless/banks/norwegian_xx_norwnok1.ts
var norwegian_xx_norwnok1_exports = /* @__PURE__ */ __exportAll({ default: () => norwegian_xx_norwnok1_default });
var norwegian_xx_norwnok1_default = {
	...integration_bank_default,
	institutionIds: [
		"NORWEGIAN_NO_NORWNOK1",
		"NORWEGIAN_SE_NORWNOK1",
		"NORWEGIAN_DE_NORWNOK1",
		"NORWEGIAN_DK_NORWNOK1",
		"NORWEGIAN_ES_NORWNOK1",
		"NORWEGIAN_FI_NORWNOK1"
	],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		if (booked) {
			editedTrans.date = transaction.bookingDate;
			return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
		}
		/**
		* For pending transactions there are two possibilities:
		*
		* - Either a `valueDate` was set, in which case it corresponds to when the
		*   transaction actually occurred, or
		* - There is no date field, in which case we try to parse the correct date
		*   out of the `remittanceInformationStructured` field.
		*
		* If neither case succeeds then we return `null` causing this transaction
		* to be filtered out for now, and hopefully we'll be able to import it
		* once the bank has processed it further.
		*/
		if (transaction.valueDate !== void 0) {
			editedTrans.date = transaction.valueDate;
			return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
		}
		if (transaction.remittanceInformationStructured) {
			const matches = transaction.remittanceInformationStructured.match(/ (\d{4}-\d{2}-\d{2}) /);
			if (matches) {
				editedTrans.date = matches[1];
				return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
			}
		}
		return null;
	},
	/**
	*  For NORWEGIAN_XX_NORWNOK1 we don't know what balance was
	*  after each transaction so we have to calculate it by getting
	*  current balance from the account and subtract all the transactions
	*
	*  As a current balance we use `expected` balance type because it
	*  corresponds to the current running balance, whereas `interimAvailable`
	*  holds the remaining credit limit.
	*/
	calculateStartingBalance(sortedTransactions = [], balances = []) {
		const currentBalance = balances.find((balance) => "expected" === balance.balanceType);
		return sortedTransactions.reduce((total, trans) => {
			return total - amountToInteger(trans.transactionAmount.amount);
		}, amountToInteger(currentBalance?.balanceAmount.amount || 0));
	}
};
//#endregion
//#region src/app-gocardless/banks/raiffeisen_at_rzbaatww.ts
var raiffeisen_at_rzbaatww_exports = /* @__PURE__ */ __exportAll({ default: () => raiffeisen_at_rzbaatww_default });
var raiffeisen_at_rzbaatww_default = {
	...integration_bank_default,
	institutionIds: ["RAIFFEISEN_AT_RZBAATWW"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		let payeeName = formatPayeeName(transaction);
		if (!payeeName) payeeName = extractPayeeName(transaction);
		editedTrans.payeeName = payeeName;
		editedTrans.remittanceInformationUnstructured = transaction.remittanceInformationUnstructured ?? transaction.remittanceInformationStructured ?? transaction.endToEndId;
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
function extractPayeeName(transaction) {
	const structured = transaction.remittanceInformationStructured ?? "";
	const matches = structured.match(/(.{12}) \d{4} .* \d{2}\.\d{2}\. \d{2}:\d{2}/);
	if (matches && matches.length > 1 && matches[1]) return title(matches[1]);
	else return structured;
}
//#endregion
//#region src/app-gocardless/banks/revolut_revolt21.ts
var revolut_revolt21_exports = /* @__PURE__ */ __exportAll({ default: () => revolut_revolt21_default });
var revolut_revolt21_default = {
	...integration_bank_default,
	institutionIds: ["REVOLUT_REVOLT21"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		const infoArray = transaction.remittanceInformationUnstructuredArray ?? [];
		if (infoArray[0]?.startsWith("Bizum payment from: ")) {
			editedTrans.payeeName = infoArray[0].replace("Bizum payment from: ", "");
			editedTrans.remittanceInformationUnstructured = infoArray[1];
		}
		if (infoArray[0]?.startsWith("Bizum payment to: ")) editedTrans.remittanceInformationUnstructured = infoArray[1];
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
//#endregion
//#region src/app-gocardless/banks/sandboxfinance_sfin0000.ts
var sandboxfinance_sfin0000_exports = /* @__PURE__ */ __exportAll({ default: () => sandboxfinance_sfin0000_default });
var sandboxfinance_sfin0000_default = {
	...integration_bank_default,
	institutionIds: ["SANDBOXFINANCE_SFIN0000"],
	/**
	*  For SANDBOXFINANCE_SFIN0000 we don't know what balance was
	*  after each transaction so we have to calculate it by getting
	*  current balance from the account and subtract all the transactions
	*
	*  As a current balance we use `interimBooked` balance type because
	*  it includes transaction placed during current day
	*/
	calculateStartingBalance(sortedTransactions = [], balances = []) {
		const currentBalance = balances.find((balance) => "interimAvailable" === balance.balanceType);
		return sortedTransactions.reduce((total, trans) => {
			return total - amountToInteger(trans.transactionAmount.amount);
		}, amountToInteger(currentBalance?.balanceAmount.amount || 0));
	}
};
//#endregion
//#region src/app-gocardless/banks/seb_kort_bank_ab.ts
var seb_kort_bank_ab_exports = /* @__PURE__ */ __exportAll({ default: () => seb_kort_bank_ab_default });
var seb_kort_bank_ab_default = {
	...integration_bank_default,
	institutionIds: [
		"SEB_KORT_AB_NO_SKHSFI21",
		"SEB_KORT_AB_SE_SKHSFI21",
		"SEB_CARD_ESSESESS",
		"NORDIC_CHOICE_CLUB_NO_SKHSFI21",
		"NORDIC_CHOICE_CLUB_SE_SKHSFI21",
		"EUROCARD_SE_SKHSFI21",
		"EUROCARD_DK_SKHSFI21",
		"EUROCARD_FI_SKHSFI21",
		"EUROCARD_NO_SKHSFI21",
		"GLOBECARD_DK_SKHSFI21",
		"GLOBECARD_NO_SKHSFI21",
		"OPEL_MASTERCARD_SKHSFI21",
		"SAAB_MASTERCARD_SKHSFI21",
		"SAS_MASTERCARD_NO_SKHSFI21",
		"SAS_MASTERCARD_SE_SKHSFI21",
		"SAS_MASTERCARD_FI_SKHSFI21",
		"SAS_MASTERCARD_DK_SKHSFI21",
		"SJ_PRIO_MASTERCARD_SKHSFI21",
		"CIRCLE_K_MASTERCARD_NO_SKHSFI21",
		"CIRCLE_K_MASTERCARD_SE_SKHSFI21",
		"CIRCLE_K_MASTERCARD_DK_SKHSFI21",
		"WALLET_SKHSFI21",
		"INGO_MASTERCARD_SKHSFI21",
		"SCANDIC_SKHSFI21"
	],
	/**
	* Sign of transaction amount needs to be flipped for SEB credit cards
	*/
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		editedTrans.creditorName = transaction.additionalInformation;
		transaction.transactionAmount = {
			amount: (-parseFloat(transaction.transactionAmount.amount)).toString(),
			currency: transaction.transactionAmount.currency
		};
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	},
	/**
	*  For SEB_KORT_AB_NO_SKHSFI21 and SEB_KORT_AB_SE_SKHSFI21 we don't know what balance was
	*  after each transaction so we have to calculate it by getting
	*  current balance from the account and subtract all the transactions
	*
	*  As a current balance we use `expected` and `nonInvoiced` balance types because it
	*  corresponds to the current running balance, whereas `interimAvailable`
	*  holds the remaining credit limit.
	*/
	calculateStartingBalance(sortedTransactions = [], balances = []) {
		const currentBalance = balances.find((balance) => "expected" === balance.balanceType);
		const nonInvoiced = balances.find((balance) => "nonInvoiced" === balance.balanceType);
		return sortedTransactions.reduce((total, trans) => {
			return total - amountToInteger(trans.transactionAmount.amount);
		}, -amountToInteger(currentBalance?.balanceAmount.amount || 0) + amountToInteger(nonInvoiced?.balanceAmount.amount || 0));
	}
};
//#endregion
//#region src/app-gocardless/banks/seb_privat.ts
var seb_privat_exports = /* @__PURE__ */ __exportAll({ default: () => seb_privat_default });
var seb_privat_default = {
	...integration_bank_default,
	institutionIds: ["SEB_ESSESESS_PRIVATE"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		editedTrans.creditorName = transaction.additionalInformation;
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	},
	calculateStartingBalance(sortedTransactions = [], balances = []) {
		const currentBalance = balances.find((balance) => "interimBooked" === balance.balanceType);
		return sortedTransactions.reduce((total, trans) => {
			return total - amountToInteger(trans.transactionAmount.amount);
		}, amountToInteger(currentBalance?.balanceAmount.amount || 0));
	}
};
//#endregion
//#region src/app-gocardless/banks/sparnord_spnodk22.ts
var sparnord_spnodk22_exports = /* @__PURE__ */ __exportAll({ default: () => sparnord_spnodk22_default });
var sparnord_spnodk22_default = {
	...integration_bank_default,
	institutionIds: [
		"SPARNORD_SPNODK22",
		"LAGERNES_BANK_LAPNDKK1",
		"ANDELSKASSEN_FALLESKASSEN_FAELDKK1"
	],
	/**
	* Banks on the BEC backend only give information regarding the transaction in additionalInformation
	*/
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		editedTrans.remittanceInformationUnstructured = transaction.additionalInformation;
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
//#endregion
//#region src/app-gocardless/banks/spk_karlsruhe_karsde66.ts
var spk_karlsruhe_karsde66_exports = /* @__PURE__ */ __exportAll({ default: () => spk_karlsruhe_karsde66_default });
var spk_karlsruhe_karsde66_default = {
	...integration_bank_default,
	institutionIds: ["SPK_KARLSRUHE_KARSDE66XXX"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		let remittanceInformationUnstructured;
		if (transaction.remittanceInformationUnstructured) remittanceInformationUnstructured = transaction.remittanceInformationUnstructured;
		else if (transaction.remittanceInformationStructured) remittanceInformationUnstructured = transaction.remittanceInformationStructured;
		else if ((transaction.remittanceInformationStructuredArray?.length ?? 0) > 0) remittanceInformationUnstructured = transaction.remittanceInformationStructuredArray?.join(" ");
		if (transaction.additionalInformation) remittanceInformationUnstructured += " " + transaction.additionalInformation;
		editedTrans.creditorName = transaction.ultimateCreditor || transaction.creditorName || transaction.debtorName;
		editedTrans.remittanceInformationUnstructured = remittanceInformationUnstructured;
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	},
	/**
	*  For SANDBOXFINANCE_SFIN0000 we don't know what balance was
	*  after each transaction so we have to calculate it by getting
	*  current balance from the account and subtract all the transactions
	*
	*  As a current balance we use `interimBooked` balance type because
	*  it includes transaction placed during current day
	*/
	calculateStartingBalance(sortedTransactions = [], balances = []) {
		const currentBalance = balances.find((balance) => "interimAvailable" === balance.balanceType);
		return sortedTransactions.reduce((total, trans) => {
			return total - amountToInteger(trans.transactionAmount.amount);
		}, amountToInteger(currentBalance?.balanceAmount.amount || 0));
	}
};
//#endregion
//#region src/app-gocardless/banks/spk_marburg_biedenkopf_heladef1mar.ts
var spk_marburg_biedenkopf_heladef1mar_exports = /* @__PURE__ */ __exportAll({ default: () => spk_marburg_biedenkopf_heladef1mar_default });
var spk_marburg_biedenkopf_heladef1mar_default = {
	...integration_bank_default,
	institutionIds: ["SPK_MARBURG_BIEDENKOPF_HELADEF1MAR"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		let remittanceInformationUnstructured;
		if (transaction.remittanceInformationUnstructured) remittanceInformationUnstructured = transaction.remittanceInformationUnstructured;
		else if (transaction.remittanceInformationStructured) remittanceInformationUnstructured = transaction.remittanceInformationStructured;
		else if ((transaction.remittanceInformationStructuredArray?.length ?? 0) > 0) remittanceInformationUnstructured = transaction.remittanceInformationStructuredArray?.join(" ");
		editedTrans.remittanceInformationUnstructured = remittanceInformationUnstructured;
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
//#endregion
//#region src/app-gocardless/banks/spk_worms_alzey_ried_malade51wor.ts
var spk_worms_alzey_ried_malade51wor_exports = /* @__PURE__ */ __exportAll({ default: () => spk_worms_alzey_ried_malade51wor_default });
var spk_worms_alzey_ried_malade51wor_default = {
	...integration_bank_default,
	institutionIds: ["SPK_WORMS_ALZEY_RIED_MALADE51WOR"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		editedTrans.remittanceInformationUnstructured = transaction.remittanceInformationUnstructured ?? transaction.remittanceInformationStructured ?? transaction.remittanceInformationStructuredArray?.join(" ");
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
//#endregion
//#region src/app-gocardless/banks/ssk_dusseldorf_dussdeddxxx.ts
var ssk_dusseldorf_dussdeddxxx_exports = /* @__PURE__ */ __exportAll({ default: () => ssk_dusseldorf_dussdeddxxx_default });
var ssk_dusseldorf_dussdeddxxx_default = {
	...integration_bank_default,
	institutionIds: ["SSK_DUSSELDORF_DUSSDEDDXXX"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		if (!booked) {
			console.debug("Skipping unbooked transaction:", transaction.transactionId);
			return null;
		}
		let remittanceInformationUnstructured = transaction.remittanceInformationUnstructured ?? transaction.remittanceInformationStructured ?? transaction.remittanceInformationStructuredArray?.join(" ");
		if (transaction.additionalInformation) remittanceInformationUnstructured = [remittanceInformationUnstructured, transaction.additionalInformation].filter(Boolean).join(" ");
		editedTrans.creditorName = transaction.ultimateCreditor || transaction.creditorName || transaction.debtorName;
		editedTrans.remittanceInformationUnstructured = remittanceInformationUnstructured;
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
//#endregion
//#region src/app-gocardless/banks/ssk_munchen.ts
/**
*  Credit for this code goes to Nebukadneza at https://github.com/Nebukadneza
*/
var ssk_munchen_exports = /* @__PURE__ */ __exportAll({ default: () => ssk_munchen_default });
var ssk_munchen_default = {
	...integration_bank_default,
	institutionIds: ["SSK_MUNCHEN_SSKMDEMMXXX"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		let remittanceInformationUnstructured;
		if (transaction.remittanceInformationUnstructured) remittanceInformationUnstructured = transaction.remittanceInformationUnstructured;
		else if (transaction.remittanceInformationStructured) remittanceInformationUnstructured = transaction.remittanceInformationStructured;
		else if ((transaction.remittanceInformationStructuredArray?.length ?? 0) > 0) remittanceInformationUnstructured = transaction.remittanceInformationStructuredArray?.join(" ");
		if (transaction.additionalInformation) remittanceInformationUnstructured += " " + transaction.additionalInformation;
		editedTrans.creditorName = transaction.ultimateCreditor || transaction.creditorName || transaction.debtorName;
		editedTrans.remittanceInformationUnstructured = remittanceInformationUnstructured;
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	},
	/**
	*  For SANDBOXFINANCE_SFIN0000 we don't know what balance was
	*  after each transaction so we have to calculate it by getting
	*  current balance from the account and subtract all the transactions
	*
	*  As a current balance we use `interimBooked` balance type because
	*  it includes transaction placed during current day
	*/
	calculateStartingBalance(sortedTransactions = [], balances = []) {
		const currentBalance = balances.find((balance) => "interimAvailable" === balance.balanceType);
		return sortedTransactions.reduce((total, trans) => {
			return total - amountToInteger(trans.transactionAmount.amount);
		}, amountToInteger(currentBalance?.balanceAmount.amount || 0));
	}
};
//#endregion
//#region src/app-gocardless/banks/swedbank_habalv22.ts
var swedbank_habalv22_exports = /* @__PURE__ */ __exportAll({ default: () => swedbank_habalv22_default });
var swedbank_habalv22_default = {
	...integration_bank_default,
	institutionIds: ["SWEDBANK_HABALV22"],
	/**
	* The actual transaction date for card transactions is only available in the remittanceInformationUnstructured field when the transaction is booked.
	*/
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		if (transaction.remittanceInformationUnstructured?.startsWith("PIRKUMS")) {
			if (!booked && !transaction.creditorName) {
				const creditorNameMatch = transaction.remittanceInformationUnstructured?.match(/PIRKUMS [\d*]+ \d{2}\.\d{2}\.\d{2} \d{2}:\d{2} [\d.]+ \w{3} \(\d+\) (.+)/);
				if (creditorNameMatch) editedTrans.creditorName = creditorNameMatch[1];
			}
			const dateMatch = transaction.remittanceInformationUnstructured?.match(/PIRKUMS [\d*]+ (\d{2}\.\d{2}\.\d{4})/);
			if (dateMatch) editedTrans.date = d.parse(dateMatch[1], "dd.MM.yyyy", /* @__PURE__ */ new Date()).toISOString();
		}
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
//#endregion
//#region src/app-gocardless/banks/virgin_nrnbgb22.ts
var virgin_nrnbgb22_exports = /* @__PURE__ */ __exportAll({ default: () => virgin_nrnbgb22_default });
var virgin_nrnbgb22_default = {
	...integration_bank_default,
	institutionIds: ["VIRGIN_NRNBGB22"],
	normalizeTransaction(transaction, booked) {
		const editedTrans = { ...transaction };
		const transferPrefixes = ["MOB", "FPS"];
		const methodRegex = /^(Card|WLT)\s\d+/;
		const parts = (transaction.remittanceInformationUnstructured ?? "").split(", ");
		if (transferPrefixes.includes(parts[0])) {
			editedTrans.creditorName = parts[1];
			editedTrans.debtorName = parts[1];
			editedTrans.remittanceInformationUnstructured = parts[2];
		} else if (parts[0].match(methodRegex)) {
			editedTrans.creditorName = parts[1];
			editedTrans.debtorName = parts[1];
		} else {
			editedTrans.creditorName = transaction.remittanceInformationUnstructured;
			editedTrans.debtorName = transaction.remittanceInformationUnstructured;
		}
		return integration_bank_default.normalizeTransaction(transaction, booked, editedTrans);
	}
};
var banks = Object.values(/* @__PURE__ */ Object.assign({
	"./banks/abanca_caglesmm.ts": abanca_caglesmm_exports,
	"./banks/abnamro_abnanl2a.ts": abnamro_abnanl2a_exports,
	"./banks/alior_albpplpw.ts": alior_albpplpw_exports,
	"./banks/american_express_aesudef1.ts": american_express_aesudef1_exports,
	"./banks/bancsabadell_bsabesbbb.ts": bancsabadell_bsabesbbb_exports,
	"./banks/bank_of_ireland_b365_bofiie2d.ts": bank_of_ireland_b365_bofiie2d_exports,
	"./banks/bankinter_bkbkesmm.ts": bankinter_bkbkesmm_exports,
	"./banks/belfius_gkccbebb.ts": belfius_gkccbebb_exports,
	"./banks/berliner_sparkasse_beladebexxx.ts": berliner_sparkasse_beladebexxx_exports,
	"./banks/bnp_be_gebabebb.ts": bnp_be_gebabebb_exports,
	"./banks/boursobank_bousfrppxxx.ts": boursobank_bousfrppxxx_exports,
	"./banks/bper_retail_bpmoit22.ts": bper_retail_bpmoit22_exports,
	"./banks/cbc_cregbebb.ts": cbc_cregbebb_exports,
	"./banks/cetelem_cetmptp1xxx.ts": cetelem_cetmptp1xxx_exports,
	"./banks/commerzbank_cobadeff.ts": commerzbank_cobadeff_exports,
	"./banks/danskebank_privat.ts": danskebank_privat_exports,
	"./banks/direkt_heladef1822.ts": direkt_heladef1822_exports,
	"./banks/easybank_bawaatww.ts": easybank_bawaatww_exports,
	"./banks/entercard_swednokk.ts": entercard_swednokk_exports,
	"./banks/fineco_febiitm2xxx.ts": fineco_febiitm2xxx_exports,
	"./banks/fortuneo_ftnofrp1xxx.ts": fortuneo_ftnofrp1xxx_exports,
	"./banks/hype_hyeeit22.ts": hype_hyeeit22_exports,
	"./banks/ing_ingbrobu.ts": ing_ingbrobu_exports,
	"./banks/ing_ingddeff.ts": ing_ingddeff_exports,
	"./banks/ing_pl_ingbplpw.ts": ing_pl_ingbplpw_exports,
	"./banks/isybank_itbbitmm.ts": isybank_itbbitmm_exports,
	"./banks/kbc_kredbebb.ts": kbc_kredbebb_exports,
	"./banks/lhv_lhvbee22.ts": lhv_lhvbee22_exports,
	"./banks/mbank_retail_brexplpw.ts": mbank_retail_brexplpw_exports,
	"./banks/nationwide_naiagb21.ts": nationwide_naiagb21_exports,
	"./banks/nbg_ethngraaxxx.ts": nbg_ethngraaxxx_exports,
	"./banks/norwegian_xx_norwnok1.ts": norwegian_xx_norwnok1_exports,
	"./banks/raiffeisen_at_rzbaatww.ts": raiffeisen_at_rzbaatww_exports,
	"./banks/revolut_revolt21.ts": revolut_revolt21_exports,
	"./banks/sandboxfinance_sfin0000.ts": sandboxfinance_sfin0000_exports,
	"./banks/seb_kort_bank_ab.ts": seb_kort_bank_ab_exports,
	"./banks/seb_privat.ts": seb_privat_exports,
	"./banks/sparnord_spnodk22.ts": sparnord_spnodk22_exports,
	"./banks/spk_karlsruhe_karsde66.ts": spk_karlsruhe_karsde66_exports,
	"./banks/spk_marburg_biedenkopf_heladef1mar.ts": spk_marburg_biedenkopf_heladef1mar_exports,
	"./banks/spk_worms_alzey_ried_malade51wor.ts": spk_worms_alzey_ried_malade51wor_exports,
	"./banks/ssk_dusseldorf_dussdeddxxx.ts": ssk_dusseldorf_dussdeddxxx_exports,
	"./banks/ssk_munchen.ts": ssk_munchen_exports,
	"./banks/swedbank_habalv22.ts": swedbank_habalv22_exports,
	"./banks/virgin_nrnbgb22.ts": virgin_nrnbgb22_exports
})).map((m) => m.default);
function BankFactory(institutionId) {
	return banks.find((b) => b.institutionIds.includes(institutionId)) || integration_bank_default;
}
//#endregion
//#region src/app-gocardless/services/gocardless-service.ts
var debugSensitive$4 = createDebug("actual-sensitive:gocardless");
var clients = /* @__PURE__ */ new Map();
var getGocardlessClient = () => {
	const secrets = {
		secretId: secretsService.get(SecretName.gocardless_secretId),
		secretKey: secretsService.get(SecretName.gocardless_secretKey)
	};
	const hash = JSON.stringify(secrets);
	let client = clients.get(hash);
	if (!client) {
		client = new GoCardlessApi(secrets);
		clients.set(hash, client);
	}
	return client;
};
var isEuaExpiredError = (error) => {
	if (!(error instanceof GoCardlessApiError)) return false;
	const data = error.response.data;
	if (typeof data !== "object" || data === null) return false;
	const { summary } = data;
	return typeof summary === "string" && /end user agreement.*expired/i.test(summary);
};
var handleGoCardlessError = (error) => {
	switch (error instanceof GoCardlessApiError ? error.response.status : void 0) {
		case 400: throw new InvalidInputDataError(error);
		case 401:
			if (isEuaExpiredError(error)) throw new EndUserAgreementExpiredError(error);
			throw new InvalidGoCardlessTokenError(error);
		case 403: throw new AccessDeniedError(error);
		case 404: throw new NotFoundError(error);
		case 409: throw new ResourceSuspended(error);
		case 429: throw new RateLimitError(error);
		case 500: throw new UnknownError(error);
		case 503: throw new ServiceError(error);
		default: throw new GenericGoCardlessError(error);
	}
};
var goCardlessService = {
	isConfigured: () => {
		return !!(getGocardlessClient().secretId && getGocardlessClient().secretKey);
	},
	setToken: async () => {
		const isExpiredJwtToken = (token) => {
			if (!token) return true;
			try {
				const payload = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString());
				return Math.floor(Date.now() / 1e3) >= payload.exp;
			} catch {
				return true;
			}
		};
		if (isExpiredJwtToken(getGocardlessClient().token)) await client.generateToken().catch(handleGoCardlessError);
	},
	getLinkedRequisition: async (requisitionId) => {
		const requisition = await goCardlessService.getRequisition(requisitionId);
		const { status } = requisition;
		if (status !== "LN") throw new RequisitionNotLinked({ requisitionStatus: status });
		return requisition;
	},
	getRequisitionWithAccounts: async (requisitionId) => {
		const requisition = await goCardlessService.getLinkedRequisition(requisitionId);
		console.log("GoCardless requisition linked:", {
			institutionId: requisition.institution_id,
			requisitionId,
			agreementId: requisition.agreement,
			accountIds: requisition.accounts
		});
		const institutionIdSet = /* @__PURE__ */ new Set();
		const detailedAccounts = await Promise.all(requisition.accounts.map(async (accountId) => {
			const account = await goCardlessService.getDetailedAccount(accountId);
			institutionIdSet.add(account.institution_id);
			return account;
		}));
		const institutions = await Promise.all(Array.from(institutionIdSet).map(async (institutionId) => {
			return await goCardlessService.getInstitution(institutionId);
		}));
		return {
			requisition,
			accounts: (await goCardlessService.extendAccountsAboutInstitutions({
				accounts: detailedAccounts,
				institutions
			})).map((account) => {
				return BankFactory(account.institution_id).normalizeAccount(account);
			})
		};
	},
	getTransactionsWithBalance: async (requisitionId, accountId, startDate, endDate) => {
		const { institution_id, accounts: accountIds } = await goCardlessService.getLinkedRequisition(requisitionId);
		if (!accountIds.includes(accountId)) throw new AccountNotLinkedToRequisition(accountId, requisitionId);
		const [normalizedTransactions, accountBalance] = await Promise.all([goCardlessService.getNormalizedTransactions(requisitionId, accountId, startDate, endDate), goCardlessService.getBalances(accountId)]);
		const transactions = normalizedTransactions.transactions;
		const startingBalance = BankFactory(institution_id).calculateStartingBalance(transactions.booked, accountBalance.balances);
		return {
			balances: accountBalance.balances,
			institutionId: institution_id,
			startingBalance,
			transactions
		};
	},
	getNormalizedTransactions: async (requisitionId, accountId, startDate, endDate) => {
		const { institution_id, accounts: accountIds } = await goCardlessService.getLinkedRequisition(requisitionId);
		if (!accountIds.includes(accountId)) throw new AccountNotLinkedToRequisition(accountId, requisitionId);
		const transactions = await goCardlessService.getTransactions({
			institutionId: institution_id,
			accountId,
			startDate,
			endDate
		});
		const bank = BankFactory(institution_id);
		const sortedBookedTransactions = bank.sortTransactions(transactions.transactions.booked);
		const sortedPendingTransactions = bank.sortTransactions(transactions.transactions.pending);
		const allTransactions = sortedBookedTransactions.map((t) => ({
			...t,
			booked: true
		}));
		sortedPendingTransactions.forEach((t) => allTransactions.push({
			...t,
			booked: false
		}));
		return {
			institutionId: institution_id,
			transactions: {
				booked: sortedBookedTransactions,
				pending: sortedPendingTransactions,
				all: bank.sortTransactions(allTransactions)
			}
		};
	},
	createRequisition: async ({ institutionId, redirectUrl }) => {
		await goCardlessService.setToken();
		const institution = await goCardlessService.getInstitution(institutionId);
		const accountSelection = institution.supported_features?.includes("account_selection") ?? false;
		const separateContinuousHistoryConsent = institution.supported_features?.includes("separate_continuous_history_consent") ?? false;
		const body = {
			redirectUrl,
			institutionId,
			referenceId: v4(),
			accessValidForDays: institution.max_access_valid_for_days,
			maxHistoricalDays: separateContinuousHistoryConsent ? 90 : institution.transaction_total_days,
			userLanguage: "en",
			ssn: null,
			redirectImmediate: false,
			accountSelection
		};
		console.log("GoCardless requisition request:", {
			institutionId,
			accessValidForDays: body.accessValidForDays,
			maxHistoricalDays: body.maxHistoricalDays,
			transactionTotalDays: institution.transaction_total_days,
			separateContinuousHistoryConsent,
			accountSelection,
			supportedFeatures: institution.supported_features
		});
		const response = await client.initSession(body).catch(async () => {
			debugSensitive$4("Failed to link using: %O", body);
			console.log("Falling back to accessValidForDays = 90 and maxHistoricalDays = 89");
			return await client.initSession({
				...body,
				accessValidForDays: 90,
				maxHistoricalDays: 89
			}).catch(handleGoCardlessError);
		});
		const { link, id: requisitionId } = response;
		console.log("GoCardless requisition created:", {
			institutionId,
			requisitionId,
			agreementId: response.agreement
		});
		return {
			link,
			requisitionId
		};
	},
	deleteRequisition: async (requisitionId) => {
		await goCardlessService.getRequisition(requisitionId);
		return client.deleteRequisition(requisitionId).catch(handleGoCardlessError);
	},
	getRequisition: async (requisitionId) => {
		await goCardlessService.setToken();
		return client.getRequisitionById(requisitionId).catch(handleGoCardlessError);
	},
	getDetailedAccount: async (accountId) => {
		const [detailedAccount, metadataAccount] = await Promise.all([client.getDetails(accountId), client.getMetadata(accountId)]).catch(handleGoCardlessError);
		const accountDetails = detailedAccount.account ?? {};
		const truthyMetadata = Object.fromEntries(Object.entries(metadataAccount ?? {}).filter(([, v]) => v));
		return {
			...accountDetails,
			...truthyMetadata
		};
	},
	getAccountMetadata: async (accountId) => client.getMetadata(accountId).catch(handleGoCardlessError),
	getInstitutions: async (country) => client.getInstitutions(country).catch(handleGoCardlessError),
	getInstitution: async (institutionId) => client.getInstitutionById(institutionId).catch(handleGoCardlessError),
	extendAccountsAboutInstitutions: async ({ accounts, institutions }) => {
		const institutionsById = institutions.reduce((acc, institution) => {
			acc[institution.id] = institution;
			return acc;
		}, {});
		return accounts.map((account) => {
			const institution = institutionsById[account.institution_id] ?? null;
			return {
				...account,
				institution
			};
		});
	},
	getTransactions: async ({ institutionId, accountId, startDate, endDate }) => {
		const response = await client.getTransactions({
			accountId,
			dateFrom: startDate,
			dateTo: endDate
		}).catch(handleGoCardlessError);
		const bank = BankFactory(institutionId);
		response.transactions.booked = response.transactions.booked.map((transaction) => bank.normalizeTransaction(transaction, true)).filter((t) => t != null);
		response.transactions.pending = response.transactions.pending.map((transaction) => bank.normalizeTransaction(transaction, false)).filter((t) => t != null);
		return response;
	},
	getBalances: async (accountId) => client.getBalances(accountId).catch(handleGoCardlessError)
};
var client = {
	getBalances: async (accountId) => await getGocardlessClient().getAccountBalances(accountId),
	getTransactions: async ({ accountId, dateFrom, dateTo }) => await getGocardlessClient().getAccountTransactions({
		accountId,
		dateFrom,
		dateTo
	}),
	getInstitutions: async (country) => await getGocardlessClient().getInstitutions({ country }),
	getInstitutionById: async (institutionId) => await getGocardlessClient().getInstitutionById(institutionId),
	getDetails: async (accountId) => await getGocardlessClient().getAccountDetails(accountId),
	getMetadata: async (accountId) => await getGocardlessClient().getAccountMetadata(accountId),
	getRequisitionById: async (requisitionId) => await getGocardlessClient().getRequisitionById(requisitionId),
	deleteRequisition: async (requisitionId) => await getGocardlessClient().deleteRequisition(requisitionId),
	initSession: async ({ redirectUrl, institutionId, referenceId, accessValidForDays, maxHistoricalDays, userLanguage, ssn, redirectImmediate, accountSelection }) => await getGocardlessClient().initSession({
		redirectUrl,
		institutionId,
		referenceId,
		accessValidForDays,
		maxHistoricalDays,
		userLanguage,
		ssn,
		redirectImmediate,
		accountSelection
	}),
	generateToken: async () => await getGocardlessClient().generateToken(),
	exchangeToken: async ({ refreshToken }) => await getGocardlessClient().exchangeToken({ refreshToken })
};
//#endregion
//#region src/app-gocardless/app-gocardless.ts
function isRecord(value) {
	return typeof value === "object" && value !== null;
}
var debugSensitive$3 = createDebug("actual-sensitive:gocardless");
var ELECTRON_APP_ORIGIN = "app://actual";
function validateOrigin(origin) {
	let url;
	try {
		url = new URL(origin ?? "");
	} catch {
		throw new Error("Invalid Origin header");
	}
	if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error("Invalid Origin header");
	return url.origin;
}
function resolveRedirectHost(req, returnToApp) {
	const { origin } = req.headers;
	const host = req.get("host");
	if ((origin === ELECTRON_APP_ORIGIN || returnToApp) && host) return `${req.protocol}://${host}`;
	return validateOrigin(origin);
}
var SAFE_ID = /^[a-zA-Z0-9_-]+$/;
function sanitizeId(id) {
	if (typeof id !== "string" || !SAFE_ID.test(id)) throw new Error(`Invalid GoCardless identifier: ${String(id)}`);
	return id;
}
var LINK_PAGE_HTML = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Actual</title>
  </head>
  <body>
    <script>
      window.close();
    <\/script>

    <p>Please wait...</p>
    <p>
      The window should close automatically. If nothing happened you can close
      this window or tab.
    </p>
  </body>
</html>`;
var app$6 = express();
app$6.use(requestLoggerMiddleware);
app$6.get("/link", function(req, res) {
	res.send(LINK_PAGE_HTML);
});
app$6.get("/link/app", function(req, res) {
	res.send(MOBILE_APP_RETURN_PAGE_HTML);
});
app$6.use(express.json());
app$6.use(validateSessionMiddleware);
app$6.post("/status", async (req, res) => {
	res.send({
		status: "ok",
		data: { configured: goCardlessService.isConfigured() }
	});
});
var ensureConfigured = (_req, res, next) => {
	if (!goCardlessService.isConfigured()) {
		res.send({
			status: "ok",
			data: {
				error_type: "GOCARDLESS_NOT_CONFIGURED",
				error_code: "GOCARDLESS_NOT_CONFIGURED",
				reason: "GoCardless credentials are missing"
			}
		});
		return;
	}
	next();
};
app$6.post("/create-web-token", handleError(async (req, res) => {
	const { institutionId: rawInstitutionId } = req.body || {};
	const institutionId = sanitizeId(rawInstitutionId);
	const returnToApp = req.body?.returnToApp === true;
	const host = resolveRedirectHost(req, returnToApp);
	const { link, requisitionId } = await goCardlessService.createRequisition({
		institutionId,
		redirectUrl: host + (returnToApp ? "/gocardless/link/app" : "/gocardless/link")
	});
	res.send({
		status: "ok",
		data: {
			link,
			requisitionId
		}
	});
}));
app$6.post("/get-accounts", handleError(async (req, res) => {
	const requisitionId = sanitizeId((req.body || {}).requisitionId);
	try {
		const { requisition, accounts } = await goCardlessService.getRequisitionWithAccounts(requisitionId);
		res.send({
			status: "ok",
			data: {
				...requisition,
				accounts: await Promise.all(accounts.map(async (account) => account?.iban ? {
					...account,
					iban: sha256String(account.iban)
				} : account))
			}
		});
	} catch (error) {
		if (error instanceof RequisitionNotLinked) res.send({
			status: "ok",
			requisitionStatus: isRecord(error.details) ? error.details.requisitionStatus : void 0
		});
		else throw error;
	}
}));
app$6.post("/get-banks", handleError(async (req, res) => {
	const { country: rawCountry, showDemo = false } = req.body || {};
	const country = sanitizeId(rawCountry);
	await goCardlessService.setToken();
	const data = await goCardlessService.getInstitutions(country);
	res.send({
		status: "ok",
		data: showDemo ? [{
			id: "SANDBOXFINANCE_SFIN0000",
			name: "DEMO bank (used for testing bank-sync)"
		}, ...data] : data
	});
}));
app$6.post("/remove-account", handleError(async (req, res) => {
	const requisitionId = sanitizeId((req.body || {}).requisitionId);
	const data = await goCardlessService.deleteRequisition(requisitionId);
	if (data.summary === "Requisition deleted") res.send({
		status: "ok",
		data
	});
	else res.send({
		status: "error",
		data: {
			data,
			reason: "Can not delete requisition"
		}
	});
}));
app$6.post("/transactions", ensureConfigured, handleError(async (req, res) => {
	const { requisitionId: rawRequisitionId, startDate, endDate, accountId: rawAccountId, includeBalance = true } = req.body || {};
	const requisitionId = sanitizeId(rawRequisitionId);
	const accountId = sanitizeId(rawAccountId);
	try {
		if (includeBalance) {
			const { balances, institutionId, startingBalance, transactions: { booked, pending, all } } = await goCardlessService.getTransactionsWithBalance(requisitionId, accountId, startDate, endDate);
			res.send({
				status: "ok",
				data: {
					balances,
					institutionId,
					startingBalance,
					transactions: {
						booked,
						pending,
						all
					}
				}
			});
		} else {
			const { institutionId, transactions: { booked, pending, all } } = await goCardlessService.getNormalizedTransactions(requisitionId, accountId, startDate, endDate);
			res.send({
				status: "ok",
				data: {
					institutionId,
					transactions: {
						booked,
						pending,
						all
					}
				}
			});
		}
	} catch (error) {
		const errorDetails = error instanceof RequisitionNotLinked || error instanceof GenericGoCardlessError || error instanceof GoCardlessClientError || error instanceof AccountNotLinkedToRequisition ? error.details : void 0;
		const responseHeaders = isRecord(errorDetails) && isRecord(errorDetails.response) ? errorDetails.response.headers : void 0;
		const rateLimitHeaders = isRecord(responseHeaders) ? Object.fromEntries(Object.entries(responseHeaders).filter(([key]) => key.startsWith("x-ratelimit-"))) : {};
		const errorMessage = error instanceof Error && error.message ? error.message : String(error);
		const sendErrorResponse = (data) => res.send({
			status: "ok",
			data: {
				...data,
				details: errorDetails,
				rateLimitHeaders
			}
		});
		switch (true) {
			case error instanceof RequisitionNotLinked:
			case error instanceof EndUserAgreementExpiredError:
				sendErrorResponse({
					error_type: "ITEM_ERROR",
					error_code: "ITEM_LOGIN_REQUIRED",
					status: "expired",
					reason: "Access to account has expired as set in End User Agreement"
				});
				break;
			case error instanceof AccountNotLinkedToRequisition:
				sendErrorResponse({
					error_type: "INVALID_INPUT",
					error_code: "INVALID_ACCESS_TOKEN",
					status: "rejected",
					reason: "Account not linked with this requisition"
				});
				break;
			case error instanceof RateLimitError:
				sendErrorResponse({
					error_type: "RATE_LIMIT_EXCEEDED",
					error_code: "NORDIGEN_ERROR",
					status: "rejected",
					reason: "Rate limit exceeded"
				});
				break;
			case error instanceof GenericGoCardlessError:
				console.log("GoCardless synchronization failed");
				debugSensitive$3("GoCardless synchronization failed: %s", errorMessage);
				sendErrorResponse({
					error_type: "SYNC_ERROR",
					error_code: "NORDIGEN_ERROR"
				});
				break;
			default:
				console.log("GoCardless synchronization failed");
				debugSensitive$3("GoCardless synchronization failed: %s", errorMessage);
				sendErrorResponse({
					error_type: "UNKNOWN",
					error_code: "UNKNOWN",
					reason: "Something went wrong"
				});
		}
	}
}));
//#endregion
//#region src/app-openid.ts
var app$5 = express();
app$5.use(express.json());
app$5.use(express.urlencoded({ extended: true }));
app$5.use(requestLoggerMiddleware);
var openIdConfigRateLimiter = rateLimit({
	windowMs: 9e5,
	max: 5,
	legacyHeaders: false,
	standardHeaders: true,
	message: {
		status: "error",
		reason: "too-many-requests"
	}
});
app$5.post("/enable", validateSessionMiddleware, async (req, res) => {
	if (!isAdmin(res.locals.user_id)) {
		res.status(403).send({
			status: "error",
			reason: "forbidden",
			details: "permission-not-found"
		});
		return;
	}
	const { error } = await enableOpenID(req.body) || {};
	if (error) {
		res.status(500).send({
			status: "error",
			reason: error
		});
		return;
	}
	res.send({ status: "ok" });
});
app$5.post("/disable", validateSessionMiddleware, async (req, res) => {
	if (!isAdmin(res.locals.user_id)) {
		res.status(403).send({
			status: "error",
			reason: "forbidden",
			details: "permission-not-found"
		});
		return;
	}
	const { error } = await disableOpenID(req.body) || {};
	if (error) {
		res.status(401).send({
			status: "error",
			reason: error
		});
		return;
	}
	res.send({ status: "ok" });
});
app$5.post("/config", openIdConfigRateLimiter, async (req, res) => {
	if (getOwnerCount() > 0) {
		res.status(400).send({
			status: "error",
			reason: "already-bootstraped"
		});
		return;
	}
	if (!await checkPassword(req.body.password)) {
		res.status(400).send({
			status: "error",
			reason: "invalid-password"
		});
		return;
	}
	const auth = getOpenIDConfig();
	if (!auth) {
		res.status(500).send({
			status: "error",
			reason: "OpenID configuration not found"
		});
		return;
	}
	try {
		const openIdConfig = JSON.parse(auth.extra_data);
		res.send({
			status: "ok",
			data: { openId: openIdConfig }
		});
	} catch {
		res.status(500).send({
			status: "error",
			reason: "Invalid OpenID configuration"
		});
	}
});
app$5.get("/callback", async (req, res) => {
	const { error, url } = await loginWithOpenIdFinalize(req.query);
	if (error) {
		res.status(400).send({
			status: "error",
			reason: error
		});
		return;
	}
	if (!isValidRedirectUrl(url)) {
		res.status(400).send({
			status: "error",
			reason: "Invalid redirect URL"
		});
		return;
	}
	res.redirect(url);
});
app$5.use(errorMiddleware);
//#endregion
//#region src/app-pluggyai/pluggyai-service.js
var debugSensitive$2 = createDebug("actual-sensitive:pluggy");
var pluggyClients = /* @__PURE__ */ new Map();
function hasCredentials(fileId = null) {
	return !!(secretsService.get(SecretName.pluggyai_clientId, fileId) && secretsService.get(SecretName.pluggyai_clientSecret, fileId) && secretsService.get(SecretName.pluggyai_itemIds, fileId));
}
function getCredentialSource(fileId, allowGlobal = true) {
	if (!!fileId && hasCredentials(fileId)) return "per-budget-file";
	if (allowGlobal && hasCredentials()) return "global";
	return null;
}
function getCredentialsCacheEntry(credentialFileId) {
	const clientId = secretsService.get(SecretName.pluggyai_clientId, credentialFileId);
	const clientSecret = secretsService.get(SecretName.pluggyai_clientSecret, credentialFileId);
	return {
		cacheKey: JSON.stringify({
			fileId: credentialFileId,
			[SecretName.pluggyai_clientId]: clientId,
			[SecretName.pluggyai_clientSecret]: clientSecret
		}),
		clientId,
		clientSecret
	};
}
function getPluggyClient(fileId, allowGlobal) {
	const credentialSource = getCredentialSource(fileId, allowGlobal);
	if (!credentialSource) throw new Error("Pluggy credentials are not configured");
	const { cacheKey, clientId, clientSecret } = getCredentialsCacheEntry(credentialSource === "per-budget-file" ? fileId : null);
	let pluggyClient = pluggyClients.get(cacheKey);
	if (!pluggyClient) {
		pluggyClient = new PluggyClient({
			clientId,
			clientSecret
		});
		pluggyClients.set(cacheKey, pluggyClient);
	}
	return pluggyClient;
}
var pluggyaiService = {
	isConfigured: (fileId) => getCredentialSource(fileId) != null,
	getCredentialSource,
	getAccountsByItemId: async (itemId, fileId, allowGlobal = true) => {
		try {
			const { results, total, ...rest } = await getPluggyClient(fileId, allowGlobal).fetchAccounts(itemId);
			return {
				results,
				total,
				...rest,
				hasError: false,
				errors: {}
			};
		} catch (error) {
			console.error("Error fetching accounts");
			debugSensitive$2("Error fetching accounts: %O", error);
			throw error;
		}
	},
	getAccountById: async (accountId, fileId, allowGlobal = true) => {
		try {
			return {
				...await getPluggyClient(fileId, allowGlobal).fetchAccount(accountId),
				hasError: false,
				errors: {}
			};
		} catch (error) {
			console.error("Error fetching account");
			debugSensitive$2("Error fetching account: %O", error);
			throw error;
		}
	},
	getTransactionsByAccountId: async (accountId, startDate, fileId, allowGlobal = true) => {
		try {
			const client = getPluggyClient(fileId, allowGlobal);
			const sandboxAccount = (await pluggyaiService.getAccountById(accountId, fileId, allowGlobal)).owner === "John Doe";
			if (sandboxAccount) startDate = "2000-01-01";
			let transactions = await client.fetchAllTransactions(accountId, { dateFrom: startDate });
			if (sandboxAccount) transactions = transactions.map((t) => ({
				...t,
				sandbox: true
			}));
			return {
				...transactions,
				hasError: false,
				errors: {}
			};
		} catch (error) {
			console.error("Error fetching transactions");
			debugSensitive$2("Error fetching transactions: %O", error);
			throw error;
		}
	}
};
//#endregion
//#region src/app-pluggyai/app-pluggyai.js
var app$4 = express();
app$4.use(requestLoggerMiddleware);
app$4.use(express.json());
app$4.use(validateBankSyncSession);
app$4.post("/status", handleError(async (req, res) => {
	const fileId = req.get("X-Actual-File-Id");
	if (!!fileId) {
		if (!isValidFileId(fileId)) {
			res.status(400).send({
				status: "error",
				reason: "invalid-file-id",
				details: "invalid fileId"
			});
			return;
		}
		if (!canAccessActiveFile(fileId, res.locals.user_id)) {
			res.status(403).send({
				status: "error",
				reason: "file-access-denied",
				details: "You don't have permissions over this file"
			});
			return;
		}
	}
	const source = pluggyaiService.getCredentialSource(fileId, !res.locals.apiKeyFileIds);
	res.send({
		status: "ok",
		data: {
			configured: !!source,
			source
		}
	});
}));
app$4.post("/accounts", handleError(async (req, res) => {
	const fileId = req.get("X-Actual-File-Id");
	if (!!fileId) {
		if (!isValidFileId(fileId)) {
			res.status(400).send({
				status: "error",
				reason: "invalid-file-id",
				details: "invalid fileId"
			});
			return;
		}
		if (!canAccessActiveFile(fileId, res.locals.user_id)) {
			res.status(403).send({
				status: "error",
				reason: "file-access-denied",
				details: "You don't have permissions over this file"
			});
			return;
		}
	}
	try {
		const source = pluggyaiService.getCredentialSource(fileId, !res.locals.apiKeyFileIds);
		if (!source) {
			res.status(400).send({
				status: "error",
				reason: "not-configured",
				details: "Pluggy credentials are not configured"
			});
			return;
		}
		const credentialFileId = source === "per-budget-file" ? fileId : null;
		const itemIds = (secretsService.get(SecretName.pluggyai_itemIds, credentialFileId) ?? "").split(",").map((item) => item.trim()).filter(Boolean);
		let accounts = [];
		for (const item of itemIds) {
			const partial = await pluggyaiService.getAccountsByItemId(item, fileId, !res.locals.apiKeyFileIds);
			accounts = accounts.concat(partial.results);
		}
		res.send({
			status: "ok",
			data: { accounts }
		});
	} catch (error) {
		res.send({
			status: "ok",
			data: { error: error.message }
		});
	}
}));
app$4.post("/transactions", handleError(async (req, res) => {
	const { accountId, startDate } = req.body || {};
	const fileId = req.get("X-Actual-File-Id");
	if (!!fileId) {
		if (!isValidFileId(fileId)) {
			res.status(400).send({
				status: "error",
				reason: "invalid-file-id",
				details: "invalid fileId"
			});
			return;
		}
		if (!canAccessActiveFile(fileId, res.locals.user_id)) {
			res.status(403).send({
				status: "error",
				reason: "file-access-denied",
				details: "You don't have permissions over this file"
			});
			return;
		}
	}
	try {
		if (!pluggyaiService.getCredentialSource(fileId, !res.locals.apiKeyFileIds)) {
			res.status(400).send({
				status: "error",
				reason: "not-configured",
				details: "Pluggy credentials are not configured"
			});
			return;
		}
		const account = await pluggyaiService.getAccountById(accountId, fileId, !res.locals.apiKeyFileIds);
		if (res.locals.apiKeyFileIds) {
			if (!(secretsService.get(SecretName.pluggyai_itemIds, fileId) ?? "").split(",").map((item) => item.trim()).includes(account.itemId)) {
				res.status(403).send({
					status: "error",
					reason: "file-access-denied"
				});
				return;
			}
		}
		const transactions = await pluggyaiService.getTransactionsByAccountId(accountId, startDate, fileId, !res.locals.apiKeyFileIds);
		let startingBalance = parseInt(Math.round(account.balance * 100).toString());
		if (account.type === "CREDIT") startingBalance = -startingBalance;
		const date = getDate$1(account.updatedAt);
		const balances = [{
			balanceAmount: {
				amount: startingBalance,
				currency: account.currencyCode
			},
			balanceType: "expected",
			referenceDate: date
		}];
		const all = [];
		const booked = [];
		const pending = [];
		for (const trans of Object.values(transactions)) {
			if (typeof trans !== "object" || Object.keys(trans).length === 0) continue;
			const newTrans = {};
			newTrans.booked = !(trans.status === "PENDING");
			const transactionDate = trans.date;
			if (transactionDate < startDate && !trans.sandbox) continue;
			newTrans.date = getDate$1(transactionDate);
			newTrans.payeeName = getPayeeName(trans);
			newTrans.notes = trans.descriptionRaw || trans.description;
			if (account.type === "CREDIT") {
				if (trans.amountInAccountCurrency) trans.amountInAccountCurrency *= -1;
				trans.amount *= -1;
			}
			let amountInCurrency = trans.amountInAccountCurrency ?? trans.amount;
			amountInCurrency = Math.round(amountInCurrency * 100) / 100;
			newTrans.transactionAmount = {
				amount: amountInCurrency,
				currency: trans.currencyCode
			};
			newTrans.transactionId = trans.id;
			newTrans.sortOrder = transactionDate.getTime();
			newTrans.originalDate = getDate$1(transactionDate);
			newTrans.date = getDate$1(getTransactionDateCorrected(trans));
			delete trans.amount;
			const finalTrans = {
				...flattenObject(trans),
				...newTrans
			};
			if (newTrans.booked) booked.push(finalTrans);
			else pending.push(finalTrans);
			all.push(finalTrans);
		}
		const sortFunction = (a, b) => b.sortOrder - a.sortOrder;
		const bookedSorted = booked.sort(sortFunction);
		const pendingSorted = pending.sort(sortFunction);
		const allSorted = all.sort(sortFunction);
		res.send({
			status: "ok",
			data: {
				balances,
				startingBalance,
				transactions: {
					all: allSorted,
					booked: bookedSorted,
					pending: pendingSorted
				}
			}
		});
	} catch (error) {
		res.send({
			status: "ok",
			data: { error: error.message }
		});
	}
}));
function getDate$1(date) {
	return date.toISOString().split("T")[0];
}
function flattenObject(obj, prefix = "") {
	const result = {};
	for (const [key, value] of Object.entries(obj)) {
		const newKey = prefix ? `${prefix}.${key}` : key;
		if (value === null) continue;
		if (typeof value === "object" && value !== null && !Array.isArray(value)) Object.assign(result, flattenObject(value, newKey));
		else result[newKey] = value;
	}
	return result;
}
function getPayeeName(trans) {
	if (trans.merchant && (trans.merchant.name || trans.merchant.businessName)) return trans.merchant.name || trans.merchant.businessName || "";
	if (trans.paymentData) {
		const { receiver, payer } = trans.paymentData;
		if (trans.type === "DEBIT" && receiver) return receiver.name || receiver.documentNumber?.value || "";
		if (trans.type === "CREDIT" && payer) return payer.name || payer.documentNumber?.value || "";
	}
	return "";
}
function addMonthsClamped(date, months) {
	const result = new Date(date);
	const day = result.getUTCDate();
	result.setUTCDate(1);
	result.setUTCMonth(result.getUTCMonth() + months);
	const lastDay = new Date(Date.UTC(result.getUTCFullYear(), result.getUTCMonth() + 1, 0)).getUTCDate();
	result.setUTCDate(Math.min(day, lastDay));
	return result;
}
function getTransactionDateCorrected(trans) {
	if (trans.creditCardMetadata?.installmentNumber != null) return addMonthsClamped(trans.creditCardMetadata.purchaseDate || trans.date, trans.creditCardMetadata.installmentNumber - 1);
	return trans.date;
}
//#endregion
//#region src/app-secrets.js
var app$3 = express();
app$3.use(express.json());
app$3.use(requestLoggerMiddleware);
app$3.use(validateSessionMiddleware);
function canManageGlobalSecrets(userId) {
	return isAdmin(userId);
}
function isBudgetFileOwner(fileId, userId) {
	const { granted } = checkFilePermission(fileId, userId) || { granted: 0 };
	return granted > 0;
}
function canManagePerBudgetFileSecrets(fileId, userId) {
	return isAdmin(userId) || isBudgetFileOwner(fileId, userId);
}
app$3.post("/", async (req, res) => {
	const { name, value } = req.body || {};
	const fileId = req.get("X-Actual-File-Id");
	const perBudgetFile = fileId != null;
	if (!(name in SecretName)) {
		res.status(400).send({
			status: "error",
			reason: "invalid-secret-name",
			details: "Unknown secret name"
		});
		return;
	}
	if (perBudgetFile) {
		if (!isValidFileId(fileId)) {
			res.status(400).send({
				status: "error",
				reason: "invalid-file-id",
				details: "invalid fileId"
			});
			return;
		}
		if (!canManagePerBudgetFileSecrets(fileId, res.locals.user_id)) {
			res.status(403).send({
				status: "error",
				reason: "file-access-denied",
				details: "You don't have permissions over this file"
			});
			return;
		}
	} else if (!canManageGlobalSecrets(res.locals.user_id)) {
		res.status(403).send({
			status: "error",
			reason: "not-admin",
			details: "You have to be admin to manage global secrets"
		});
		return;
	}
	const secretFileId = perBudgetFile ? fileId : null;
	secretsService.set(name, value, secretFileId);
	res.status(200).send({ status: "ok" });
});
app$3.delete("/:name", async (req, res) => {
	const name = req.params.name;
	const fileId = req.get("X-Actual-File-Id");
	const perBudgetFile = fileId != null;
	if (!(name in SecretName)) {
		res.status(404).send("key not found");
		return;
	}
	if (!perBudgetFile) {
		if (!canManageGlobalSecrets(res.locals.user_id)) {
			res.status(403).send({
				status: "error",
				reason: "not-admin",
				details: "You have to be admin to manage global secrets"
			});
			return;
		}
		secretsService.reset(name);
		res.status(200).send({ status: "ok" });
		return;
	}
	if (!isValidFileId(fileId)) {
		res.status(400).send({
			status: "error",
			reason: "invalid-file-id",
			details: "invalid fileId"
		});
		return;
	}
	if (!canManagePerBudgetFileSecrets(fileId, res.locals.user_id)) {
		res.status(403).send({
			status: "error",
			reason: "file-access-denied",
			details: "You don't have permissions over this file"
		});
		return;
	}
	secretsService.reset(name, fileId);
	res.status(200).send({ status: "ok" });
});
app$3.get("/:name", async (req, res) => {
	const name = req.params.name;
	const fileId = req.get("X-Actual-File-Id");
	const perBudgetFile = fileId != null;
	if (!(name in SecretName)) {
		res.status(404).send("key not found");
		return;
	}
	if (!perBudgetFile) {
		if (!canManageGlobalSecrets(res.locals.user_id)) {
			res.status(403).send({
				status: "error",
				reason: "not-admin",
				details: "You have to be admin to manage global secrets"
			});
			return;
		}
	} else {
		if (!isValidFileId(fileId)) {
			res.status(400).send({
				status: "error",
				reason: "invalid-file-id",
				details: "invalid fileId"
			});
			return;
		}
		if (!canManagePerBudgetFileSecrets(fileId, res.locals.user_id)) {
			res.status(403).send({
				status: "error",
				reason: "file-access-denied",
				details: "You don't have permissions over this file"
			});
			return;
		}
	}
	if (secretsService.exists(name, perBudgetFile ? fileId : null)) res.sendStatus(204);
	else res.status(404).send("key not found");
});
//#endregion
//#region src/app-simplefin/app-simplefin.js
var debugSensitive$1 = createDebug("actual-sensitive:simplefin");
var networkOptions = { allowedNetworks: configSchema.get("simplefinAllowedNetworks") };
var dispatcher = createSsrfDispatcher(networkOptions);
var app$2 = express();
app$2.use(requestLoggerMiddleware);
app$2.use(express.json());
app$2.use(validateBankSyncSession);
app$2.use((req, res, next) => {
	const fileId = req.get("X-Actual-File-Id");
	if (fileId != null) {
		if (!isValidFileId(fileId)) {
			res.status(400).send({
				status: "error",
				reason: "invalid-file-id"
			});
			return;
		}
		if (!canAccessActiveFile(fileId, res.locals.user_id)) {
			res.status(403).send({
				status: "error",
				reason: "file-access-denied"
			});
			return;
		}
	}
	res.locals.credentialFileId = fileId != null && (res.locals.apiKeyFileIds || secretsService.exists(SecretName.simplefin_token, fileId) || secretsService.exists(SecretName.simplefin_accessKey, fileId)) ? fileId : null;
	next();
});
app$2.post("/status", handleError(async (req, res) => {
	const token = secretsService.get(SecretName.simplefin_token, res.locals.credentialFileId);
	const configured = token != null && !isForbidden(token);
	res.send({
		status: "ok",
		data: {
			configured,
			source: res.locals.credentialFileId ? "per-budget-file" : configured ? "global" : null
		}
	});
}));
app$2.post("/accounts", handleError(async (req, res) => {
	let accessKey = secretsService.get(SecretName.simplefin_accessKey, res.locals.credentialFileId);
	if (isInvalidAccessKey(accessKey)) {
		const token = secretsService.get(SecretName.simplefin_token, res.locals.credentialFileId);
		if (token == null || isForbidden(token)) {
			invalidToken(res);
			return;
		}
		const claimUrl = decodeClaimUrl(token);
		if (claimUrl == null) {
			console.log("SimpleFIN setup token does not decode to a claim URL - re-enter the token");
			invalidToken(res);
			return;
		}
		try {
			accessKey = await claimAccessKey(claimUrl);
		} catch (e) {
			console.log("Failed to claim the SimpleFIN setup token:");
			serverDown(e, res);
			return;
		}
		if (isInvalidAccessKey(accessKey)) {
			console.log("SimpleFIN rejected the setup token claim");
			debugSensitive$1("SimpleFIN rejected the setup token claim: %s", accessKey.slice(0, 200) || "(empty response)");
			invalidToken(res);
			return;
		}
		secretsService.set(SecretName.simplefin_accessKey, accessKey, res.locals.credentialFileId);
	}
	try {
		const accounts = await getAccounts(accessKey, null, null, null, true);
		res.send({
			status: "ok",
			data: { accounts: accounts.accounts }
		});
	} catch (e) {
		serverDown(e, res);
		return;
	}
}));
app$2.post("/transactions", handleError(async (req, res) => {
	const { accountId, startDate } = req.body || {};
	const accessKey = secretsService.get(SecretName.simplefin_accessKey, res.locals.credentialFileId);
	if (isInvalidAccessKey(accessKey)) {
		invalidToken(res);
		return;
	}
	if (Array.isArray(accountId) !== Array.isArray(startDate)) {
		console.log({
			accountId,
			startDate
		});
		throw new Error("accountId and startDate must either both be arrays or both be strings");
	}
	if (Array.isArray(accountId) && accountId.length !== startDate.length) {
		console.log({
			accountId,
			startDate
		});
		throw new Error("accountId and startDate arrays must be the same length");
	}
	const earliestStartDate = Array.isArray(startDate) ? startDate.reduce((a, b) => a < b ? a : b) : startDate;
	let results;
	try {
		results = await getTransactions(accessKey, Array.isArray(accountId) ? accountId : [accountId], new Date(earliestStartDate));
	} catch (e) {
		if (isForbidden(e.message)) invalidToken(res);
		else serverDown(e, res);
		return;
	}
	let response = {};
	if (Array.isArray(accountId)) for (let i = 0; i < accountId.length; i++) {
		const id = accountId[i];
		response[id] = getAccountResponse(results, id, new Date(startDate[i]));
	}
	else response = getAccountResponse(results, accountId, new Date(startDate));
	if (results.hasError) {
		res.send({
			status: "ok",
			data: !Array.isArray(accountId) ? results.errors[accountId][0] : {
				...response,
				errors: results.errors
			}
		});
		return;
	}
	res.send({
		status: "ok",
		data: response
	});
}));
function logAccountError(results, accountId, data) {
	const errors = results.errors[accountId] || [];
	errors.push(data);
	results.errors[accountId] = errors;
	results.hasError = true;
}
function getAccountResponse(results, accountId, startDate) {
	const account = !results?.accounts || results.accounts.find((a) => a.id === accountId);
	if (!account) {
		console.log(`The account "${accountId}" was not found. Here were the accounts returned:`);
		if (results?.accounts) results.accounts.forEach((a) => console.log(`${a.id} - ${a.org.name}`));
		logAccountError(results, accountId, {
			error_type: "ACCOUNT_MISSING",
			error_code: "ACCOUNT_MISSING",
			reason: `The account "${accountId}" was not found. Try unlinking and relinking the account.`
		});
		return;
	}
	if (results.sferrors.find((e) => e.startsWith(`Connection to ${account.org.name} may need attention`))) logAccountError(results, accountId, {
		error_type: "ACCOUNT_NEEDS_ATTENTION",
		error_code: "ACCOUNT_NEEDS_ATTENTION",
		reason: "The account needs your attention at <a href=\"https://bridge.simplefin.org/auth/login\">SimpleFIN</a>."
	});
	const startingBalance = parseInt(account.balance.replace(".", ""));
	const date = getDate(/* @__PURE__ */ new Date(account["balance-date"] * 1e3));
	const balances = [{
		balanceAmount: {
			amount: account.balance,
			currency: account.currency
		},
		balanceType: "expected",
		referenceDate: date
	}, {
		balanceAmount: {
			amount: account.balance,
			currency: account.currency
		},
		balanceType: "interimAvailable",
		referenceDate: date
	}];
	const all = [];
	const booked = [];
	const pending = [];
	for (const trans of account.transactions) {
		const newTrans = {};
		let dateToUse = 0;
		if (trans.pending ?? trans.posted === 0) {
			newTrans.booked = false;
			dateToUse = trans.transacted_at;
		} else {
			newTrans.booked = true;
			dateToUse = trans.posted;
		}
		const transactionDate = /* @__PURE__ */ new Date(dateToUse * 1e3);
		if (transactionDate < startDate) continue;
		newTrans.sortOrder = dateToUse;
		newTrans.date = getDate(transactionDate);
		newTrans.payeeName = trans.payee;
		newTrans.notes = trans.description;
		newTrans.transactionAmount = {
			amount: trans.amount,
			currency: "USD"
		};
		newTrans.transactionId = trans.id;
		newTrans.valueDate = newTrans.bookingDate;
		if (trans.transacted_at) newTrans.transactedDate = getDate(/* @__PURE__ */ new Date(trans.transacted_at * 1e3));
		if (trans.posted) newTrans.postedDate = getDate(/* @__PURE__ */ new Date(trans.posted * 1e3));
		if (newTrans.booked) booked.push(newTrans);
		else pending.push(newTrans);
		all.push(newTrans);
	}
	const sortFunction = (a, b) => b.sortOrder - a.sortOrder;
	const bookedSorted = booked.sort(sortFunction);
	const pendingSorted = pending.sort(sortFunction);
	return {
		balances,
		startingBalance,
		transactions: {
			all: all.sort(sortFunction),
			booked: bookedSorted,
			pending: pendingSorted
		}
	};
}
function invalidToken(res) {
	res.send({
		status: "ok",
		data: {
			error_type: "INVALID_ACCESS_TOKEN",
			error_code: "INVALID_ACCESS_TOKEN",
			status: "rejected",
			reason: "Invalid SimpleFIN access token.  Reset the token and re-link any broken accounts."
		}
	});
}
function serverDown(e, res) {
	console.log("Error communicating with SimpleFIN");
	debugSensitive$1("Error communicating with SimpleFIN: %O", e);
	res.send({
		status: "ok",
		data: {
			error_type: "SERVER_DOWN",
			error_code: "SERVER_DOWN",
			status: "rejected",
			reason: "There was an error communicating with SimpleFIN."
		}
	});
}
var ACCESS_KEY_FORMAT = /^.*\/\/.*:.*@.*$/;
function parseAccessKey(accessKey) {
	let scheme = null;
	let rest = null;
	let auth = null;
	let username = null;
	let password = null;
	let baseUrl = null;
	if (!accessKey || !ACCESS_KEY_FORMAT.test(accessKey)) {
		console.log("Invalid SimpleFIN access key");
		throw new Error(`Invalid access key`);
	}
	[scheme, rest] = accessKey.split("//");
	[auth, rest] = rest.split("@");
	[username, password] = auth.split(":");
	baseUrl = `${scheme}//${rest}`;
	return {
		baseUrl,
		username,
		password
	};
}
function decodeClaimUrl(base64Token) {
	const decoded = Buffer.from(base64Token, "base64").toString();
	let url;
	try {
		url = new URL(decoded);
	} catch {
		return null;
	}
	if (url.protocol !== "https:" && url.protocol !== "http:") return null;
	return decoded;
}
async function claimAccessKey(claimUrl) {
	await assertUrlAllowed(claimUrl, networkOptions);
	const response = await fetch(claimUrl, {
		method: "POST",
		redirect: "manual",
		dispatcher
	});
	if (!response.ok && response.status !== 403) throw new Error(`SimpleFIN claim failed with HTTP ${response.status}`);
	return (await response.text()).trim();
}
function isForbidden(value) {
	return typeof value === "string" && value.startsWith("Forbidden");
}
function isInvalidAccessKey(accessKey) {
	return typeof accessKey !== "string" || isForbidden(accessKey) || !ACCESS_KEY_FORMAT.test(accessKey);
}
async function getTransactions(accessKey, accounts, startDate, endDate) {
	const now = /* @__PURE__ */ new Date();
	startDate = startDate || new Date(now.getFullYear(), now.getMonth(), 1);
	endDate = endDate || new Date(now.getFullYear(), now.getMonth() + 1, 1);
	console.log(`${getDate(startDate)} - ${getDate(endDate)}`);
	return await getAccounts(accessKey, accounts, startDate, endDate);
}
function getDate(date) {
	return date.toISOString().split("T")[0];
}
function normalizeDate(date) {
	return (date.valueOf() - date.getTimezoneOffset() * 60 * 1e3) / 1e3;
}
async function getAccounts(accessKey, accounts, startDate, endDate, noTransactions = false) {
	const sfin = parseAccessKey(accessKey);
	const headers = { Authorization: `Basic ${Buffer.from(`${sfin.username}:${sfin.password}`).toString("base64")}` };
	const params = new URLSearchParams();
	if (!noTransactions) {
		if (startDate) params.append("start-date", normalizeDate(startDate));
		if (endDate) params.append("end-date", normalizeDate(endDate));
		params.append("pending", "1");
	} else params.append("balances-only", "1");
	if (accounts) for (const id of accounts) params.append("account", id);
	const url = new URL(`${sfin.baseUrl}/accounts`);
	url.search = params.toString();
	const MAX_REDIRECTS = 5;
	let currentUrl = url.toString();
	let response;
	for (let hop = 0;; hop++) {
		await assertUrlAllowed(currentUrl, networkOptions);
		response = await fetch(currentUrl, {
			method: "GET",
			headers,
			redirect: "manual",
			dispatcher
		});
		const location = response.headers.get("location");
		if (response.status < 300 || response.status >= 400 || !location) break;
		if (hop >= MAX_REDIRECTS) throw new Error("Too many redirects");
		const nextUrl = new URL(location, currentUrl);
		if (nextUrl.origin !== new URL(currentUrl).origin) delete headers.Authorization;
		currentUrl = nextUrl.toString();
	}
	if (response.status === 403) throw new Error("Forbidden");
	const text = await response.text();
	try {
		const results = JSON.parse(text);
		results.sferrors = results.errors;
		results.hasError = false;
		results.errors = {};
		return results;
	} catch (e) {
		console.log("Error parsing SimpleFIN response");
		debugSensitive$1("Error parsing SimpleFIN response: %s", text);
		throw e;
	}
}
//#endregion
//#region ../crdt/src/crdt/merkle.ts
function isNumberTrieNodeKey(input) {
	return [
		"0",
		"1",
		"2"
	].includes(input);
}
function getKeys(trie) {
	return Object.keys(trie).filter(isNumberTrieNodeKey);
}
/**
* Mutates `trie` to insert a node at `timestamp`
*/
function insert(trie, timestamp) {
	const hash = timestamp.hash();
	const key = Number(Math.floor(timestamp.millis() / 1e3 / 60)).toString(3);
	trie = Object.assign({}, trie, { hash: (trie.hash || 0) ^ hash });
	return insertKey(trie, key, hash);
}
function insertKey(trie, key, hash) {
	if (key.length === 0) return trie;
	const c = key[0];
	const n = (isNumberTrieNodeKey(c) ? trie[c] : void 0) || {};
	return Object.assign({}, trie, { [c]: Object.assign({}, n, insertKey(n, key.slice(1), hash), { hash: (n.hash || 0) ^ hash }) });
}
function prune(trie, n = 2) {
	if (!trie.hash) return trie;
	const keys = getKeys(trie);
	keys.sort((a, b) => a.localeCompare(b));
	const next = { hash: trie.hash };
	for (const k of keys.slice(-n)) {
		const node = trie[k];
		if (!node) throw new Error(`TrieNode for key ${k} could not be found`);
		next[k] = prune(node, n);
	}
	return next;
}
//#endregion
//#region ../crdt/src/crdt/timestamp.ts
var clock;
function setClock(clock_) {
	clock = clock_;
}
function makeClock(timestamp, merkle = {}) {
	return {
		timestamp: MutableTimestamp.from(timestamp),
		merkle
	};
}
var config = { maxDrift: 3e5 };
var MAX_COUNTER = parseInt("0xFFFF");
var MAX_NODE_LENGTH = 16;
/**
* timestamp instance class
*/
var Timestamp = class Timestamp {
	constructor(millis, counter, node) {
		this._state = {
			millis,
			counter,
			node
		};
	}
	valueOf() {
		return this.toString();
	}
	toString() {
		return [
			new Date(this.millis()).toISOString(),
			("0000" + this.counter().toString(16).toUpperCase()).slice(-4),
			("0000000000000000" + this.node()).slice(-16)
		].join("-");
	}
	millis() {
		return this._state.millis;
	}
	counter() {
		return this._state.counter;
	}
	node() {
		return this._state.node;
	}
	hash() {
		return murmurhash.v3(this.toString());
	}
	static init(options = {}) {
		if (options.maxDrift) config.maxDrift = options.maxDrift;
		setClock(makeClock(new Timestamp(0, 0, options.node ? ("0000000000000000" + options.node).toString().slice(-16) : "")));
	}
	static {
		this.max = Timestamp.parse("9999-12-31T23:59:59.999Z-FFFF-FFFFFFFFFFFFFFFF");
	}
	/**
	* timestamp parsing
	* converts a fixed-length string timestamp to the structured value
	*/
	static parse(timestamp) {
		if (timestamp instanceof Timestamp) return timestamp;
		if (typeof timestamp === "string") {
			const parts = timestamp.split("-");
			if (parts && parts.length === 5) {
				const millis = Date.parse(parts.slice(0, 3).join("-")).valueOf();
				const counter = parseInt(parts[3], 16);
				const node = parts[4];
				if (!isNaN(millis) && millis >= 0 && !isNaN(counter) && counter <= MAX_COUNTER && typeof node === "string" && node.length <= MAX_NODE_LENGTH) return new Timestamp(millis, counter, node);
			}
		}
		return null;
	}
	/**
	* Timestamp send. Generates a unique, monotonic timestamp suitable
	* for transmission to another system in string format
	*/
	static send() {
		if (!clock) return null;
		const phys = Date.now();
		const lOld = clock.timestamp.millis();
		const cOld = clock.timestamp.counter();
		const lNew = Math.max(lOld, phys);
		const cNew = lOld === lNew ? cOld + 1 : 0;
		if (lNew - phys > config.maxDrift) throw new Timestamp.ClockDriftError(lNew, phys, config.maxDrift);
		if (cNew > MAX_COUNTER) throw new Timestamp.OverflowError();
		clock.timestamp.setMillis(lNew);
		clock.timestamp.setCounter(cNew);
		return new Timestamp(clock.timestamp.millis(), clock.timestamp.counter(), clock.timestamp.node());
	}
	static recv(msg) {
		if (!clock) return null;
		const phys = Date.now();
		const lMsg = msg.millis();
		const cMsg = msg.counter();
		if (lMsg - phys > config.maxDrift) throw new Timestamp.ClockDriftError();
		const lOld = clock.timestamp.millis();
		const cOld = clock.timestamp.counter();
		const lNew = Math.max(Math.max(lOld, phys), lMsg);
		const cNew = lNew === lOld && lNew === lMsg ? Math.max(cOld, cMsg) + 1 : lNew === lOld ? cOld + 1 : lNew === lMsg ? cMsg + 1 : 0;
		if (lNew - phys > config.maxDrift) throw new Timestamp.ClockDriftError();
		if (cNew > MAX_COUNTER) throw new Timestamp.OverflowError();
		clock.timestamp.setMillis(lNew);
		clock.timestamp.setCounter(cNew);
		return new Timestamp(clock.timestamp.millis(), clock.timestamp.counter(), clock.timestamp.node());
	}
	static {
		this.zero = Timestamp.parse("1970-01-01T00:00:00.000Z-0000-0000000000000000");
	}
	static {
		this.since = (isoString) => isoString + "-0000-0000000000000000";
	}
	static {
		this.DuplicateNodeError = class DuplicateNodeError extends Error {
			constructor(node) {
				super("duplicate node identifier " + node);
				this.name = "DuplicateNodeError";
			}
		};
	}
	static {
		this.ClockDriftError = class ClockDriftError extends Error {
			constructor(...args) {
				super(["maximum clock drift exceeded", ...args.map(String)].join(" "));
				this.name = "ClockDriftError";
			}
		};
	}
	static {
		this.OverflowError = class OverflowError extends Error {
			constructor() {
				super("timestamp counter overflow");
				this.name = "OverflowError";
			}
		};
	}
	static {
		this.InvalidError = class InvalidError extends Error {
			constructor(...args) {
				super(["timestamp is not valid"].concat(args.map(String)).join(" "));
				this.name = "InvalidError";
			}
		};
	}
};
var MutableTimestamp = class MutableTimestamp extends Timestamp {
	static from(timestamp) {
		return new MutableTimestamp(timestamp.millis(), timestamp.counter(), timestamp.node());
	}
	setMillis(n) {
		this._state.millis = n;
	}
	setCounter(n) {
		this._state.counter = n;
	}
	setNode(n) {
		this._state.node = n;
	}
};
//#endregion
//#region ../crdt/src/proto/sync_pb.ts
/**
* Describes the file sync.proto.
*/
var file_sync = fileDesc("CgpzeW5jLnByb3RvIjoKDUVuY3J5cHRlZERhdGESCgoCaXYYASABKAwSDwoHYXV0aFRhZxgCIAEoDBIMCgRkYXRhGAMgASgMIkYKB01lc3NhZ2USDwoHZGF0YXNldBgBIAEoCRILCgNyb3cYAiABKAkSDgoGY29sdW1uGAMgASgJEg0KBXZhbHVlGAQgASgJIkoKD01lc3NhZ2VFbnZlbG9wZRIRCgl0aW1lc3RhbXAYASABKAkSEwoLaXNFbmNyeXB0ZWQYAiABKAgSDwoHY29udGVudBgDIAEoDCJ2CgtTeW5jUmVxdWVzdBIiCghtZXNzYWdlcxgBIAMoCzIQLk1lc3NhZ2VFbnZlbG9wZRIOCgZmaWxlSWQYAiABKAkSDwoHZ3JvdXBJZBgDIAEoCRINCgVrZXlJZBgFIAEoCRINCgVzaW5jZRgGIAEoCUoECAQQBSJCCgxTeW5jUmVzcG9uc2USIgoIbWVzc2FnZXMYASADKAsyEC5NZXNzYWdlRW52ZWxvcGUSDgoGbWVya2xlGAIgASgJYgZwcm90bzM");
messageDesc(file_sync, 0);
messageDesc(file_sync, 1);
/**
* Describes the message MessageEnvelope.
* Use `create(MessageEnvelopeSchema)` to create a new message.
*/
var MessageEnvelopeSchema = messageDesc(file_sync, 2);
/**
* Describes the message SyncRequest.
* Use `create(SyncRequestSchema)` to create a new message.
*/
var SyncRequestSchema = messageDesc(file_sync, 3);
/**
* Describes the message SyncResponse.
* Use `create(SyncResponseSchema)` to create a new message.
*/
var SyncResponseSchema = messageDesc(file_sync, 4);
//#endregion
//#region src/app-sync/errors.ts
var FileNotFound = class extends Error {
	details;
	constructor(params = {}) {
		super("File does not exist or you don't have access to it");
		this.details = params;
	}
};
var GenericFileError = class extends Error {
	details;
	constructor(message, params = {}) {
		super(message);
		this.details = params;
	}
};
//#endregion
//#region src/app-sync/services/files-service.ts
var FileBase = class {
	name;
	groupId;
	encryptSalt;
	encryptTest;
	encryptKeyId;
	encryptMeta;
	syncVersion;
	deleted;
	owner;
	constructor(name, groupId, encryptSalt, encryptTest, encryptKeyId, encryptMeta, syncVersion, deleted, owner) {
		this.name = name;
		this.groupId = groupId;
		this.encryptSalt = encryptSalt;
		this.encryptTest = encryptTest;
		this.encryptKeyId = encryptKeyId;
		this.encryptMeta = encryptMeta;
		this.syncVersion = syncVersion;
		this.deleted = typeof deleted === "boolean" ? deleted : Boolean(deleted);
		this.owner = owner;
	}
};
var File = class extends FileBase {
	id;
	constructor({ id, name = null, groupId = null, encryptSalt = null, encryptTest = null, encryptKeyId = null, encryptMeta = null, syncVersion = null, deleted = false, owner = null }) {
		super(name, groupId, encryptSalt, encryptTest, encryptKeyId, encryptMeta, syncVersion, deleted, owner);
		this.id = id;
	}
};
/**
* Represents a file update. Will only update the fields that are defined.
* @class
* @extends FileBase
*/
var FileUpdate = class extends FileBase {
	constructor({ name, groupId, encryptSalt, encryptTest, encryptKeyId, encryptMeta, syncVersion, deleted, owner }) {
		super(name, groupId, encryptSalt, encryptTest, encryptKeyId, encryptMeta, syncVersion, deleted, owner);
	}
};
var boolToInt$1 = (bool) => {
	return bool ? 1 : 0;
};
var FilesService = class {
	accountDb;
	constructor(accountDb) {
		this.accountDb = accountDb;
	}
	get(fileId) {
		const rawFile = this.getRaw(fileId);
		if (!rawFile || rawFile && rawFile.deleted) throw new FileNotFound();
		return this.validate(rawFile);
	}
	set(file) {
		const deletedInt = boolToInt$1(file.deleted);
		this.accountDb.mutate("INSERT INTO files (id, group_id, sync_version, name, encrypt_meta, encrypt_salt, encrypt_test, encrypt_keyid, deleted, owner) VALUES (?, ?, ?, ?, ?, ?, ?, ? ,?, ?)", [
			file.id,
			file.groupId,
			file.syncVersion?.toString(),
			file.name,
			file.encryptMeta,
			file.encryptSalt,
			file.encryptTest,
			file.encryptKeyId,
			deletedInt,
			file.owner
		]);
	}
	find({ userId, limit = 1e3 }) {
		return (isAdmin(userId) ? this.accountDb.all("SELECT * FROM files WHERE deleted = 0 LIMIT ?", [limit]) : this.accountDb.all(`SELECT files.*
        FROM files
        WHERE files.owner = ? and deleted = 0
      UNION
       SELECT files.*
        FROM files
        JOIN user_access
          ON user_access.file_id = files.id
          AND user_access.user_id = ?
       WHERE files.deleted = 0 LIMIT ?`, [
			userId,
			userId,
			limit
		])).map((item) => this.validate(item));
	}
	findUsersWithAccess(fileId) {
		return this.accountDb.all(`SELECT UA.user_id as userId, users.display_name displayName, users.user_name userName
              FROM files
                JOIN user_access UA ON UA.file_id = files.id
                JOIN users on users.id = UA.user_id
              WHERE files.id = ?
          UNION ALL
        SELECT users.id, users.display_name, users.user_name
              FROM files
                JOIN users on users.id = files.owner
              WHERE files.id = ?
          `, [fileId, fileId]) || [];
	}
	update(id, fileUpdate) {
		let query = "UPDATE files SET";
		const params = [];
		const updates = [];
		if (fileUpdate.name !== void 0) {
			updates.push("name = ?");
			params.push(fileUpdate.name);
		}
		if (fileUpdate.groupId !== void 0) {
			updates.push("group_id = ?");
			params.push(fileUpdate.groupId);
		}
		if (fileUpdate.encryptSalt !== void 0) {
			updates.push("encrypt_salt = ?");
			params.push(fileUpdate.encryptSalt);
		}
		if (fileUpdate.encryptTest !== void 0) {
			updates.push("encrypt_test = ?");
			params.push(fileUpdate.encryptTest);
		}
		if (fileUpdate.encryptKeyId !== void 0) {
			updates.push("encrypt_keyid = ?");
			params.push(fileUpdate.encryptKeyId);
		}
		if (fileUpdate.encryptMeta !== void 0) {
			updates.push("encrypt_meta = ?");
			params.push(fileUpdate.encryptMeta);
		}
		if (fileUpdate.syncVersion !== void 0) {
			updates.push("sync_version = ?");
			params.push(fileUpdate.syncVersion);
		}
		if (fileUpdate.deleted !== void 0) {
			updates.push("deleted = ?");
			params.push(boolToInt$1(fileUpdate.deleted));
		}
		if (updates.length > 0) {
			query += " " + updates.join(", ") + " WHERE id = ?";
			params.push(id);
			if (this.accountDb.mutate(query, params).changes !== 1) throw new GenericFileError("Could not update File", { id });
		}
		const rawFile = this.getRaw(id);
		if (!rawFile) throw new GenericFileError("File not found", { id });
		return this.validate(rawFile);
	}
	getRaw(fileId) {
		return this.accountDb.first(`SELECT * FROM files WHERE id = ?`, [fileId]);
	}
	validate(rawFile) {
		const fileId = rawFile.id;
		if (!isValidFileId(fileId)) throw new GenericFileError("Invalid file ID", { fileId });
		let groupId = null;
		if (rawFile.group_id !== null) {
			if (!isValidGroupId(rawFile.group_id)) throw new GenericFileError("Invalid group ID", { groupId: rawFile.group_id });
			groupId = rawFile.group_id;
		}
		return new File({
			id: fileId,
			name: rawFile.name,
			groupId,
			encryptSalt: rawFile.encrypt_salt,
			encryptTest: rawFile.encrypt_test,
			encryptKeyId: rawFile.encrypt_keyid,
			encryptMeta: rawFile.encrypt_meta,
			syncVersion: rawFile.sync_version,
			deleted: Boolean(rawFile.deleted),
			owner: rawFile.owner
		});
	}
};
//#endregion
//#region src/app-sync/validation.ts
var SYNC_FORMAT_VERSION = 2;
var validateSyncedFile = (groupId, keyId, currentFile) => {
	if (currentFile.syncVersion == null || Number(currentFile.syncVersion) < SYNC_FORMAT_VERSION) return "file-old-version";
	if (currentFile.groupId == null) return "file-needs-upload";
	if ((currentFile.encryptMeta ? JSON.parse(currentFile.encryptMeta).keyId : null) !== currentFile.encryptKeyId) return "file-key-mismatch";
	if (groupId !== currentFile.groupId) return "file-has-reset";
	if (keyId !== currentFile.encryptKeyId) return "file-has-new-key";
	return null;
};
var validateUploadedFile = (groupId, keyId, currentFile) => {
	if (!currentFile) return null;
	if (groupId !== currentFile.groupId) return "file-has-reset";
	if (keyId !== currentFile.encryptKeyId) return "file-has-new-key";
	return null;
};
//#endregion
//#region src/sql/messages.sql?raw
var messages_default = "\nCREATE TABLE messages_binary\n  (timestamp TEXT PRIMARY KEY,\n   is_encrypted BOOLEAN,\n   content bytea);\n\nCREATE TABLE messages_merkles\n  (id INTEGER PRIMARY KEY,\n   merkle TEXT);\n";
//#endregion
//#region src/sync-simple.js
var MAX_FUTURE_DRIFT_MS = 3e5;
function getGroupDb(groupId) {
	const path = getPathForGroupFile(groupId);
	const needsInit = !existsSync(path);
	const db = openDatabase(path);
	if (needsInit) db.exec(messages_default);
	return db;
}
function addMessages(db, messages) {
	let returnValue;
	db.transaction(() => {
		let trie = getMerkle(db);
		if (messages.length > 0) {
			for (const msg of messages) if (db.mutate(`INSERT OR IGNORE INTO messages_binary (timestamp, is_encrypted, content)
             VALUES (?, ?, ?)`, [
				msg.timestamp,
				msg.isEncrypted ? 1 : 0,
				Buffer.from(msg.content)
			]).changes > 0) {
				const timestamp = Timestamp.parse(msg.timestamp);
				const error = getTimestampError(timestamp);
				if (error) throw Object.assign(new Error(error), { rejectedReason: error });
				trie = insert(trie, timestamp);
			}
		}
		trie = prune(trie);
		db.mutate("INSERT INTO messages_merkles (id, merkle) VALUES (1, ?) ON CONFLICT (id) DO UPDATE SET merkle = ?", [JSON.stringify(trie), JSON.stringify(trie)]);
		returnValue = trie;
	});
	return returnValue;
}
function getTimestampError(timestamp) {
	if (!timestamp) return "invalid-timestamp";
	if (timestamp.millis() - Date.now() > MAX_FUTURE_DRIFT_MS) return "clock-drift";
	return null;
}
function getMerkle(db) {
	const rows = db.all("SELECT * FROM messages_merkles");
	if (rows.length > 0) return JSON.parse(rows[0].merkle);
	else return {};
}
function sync(messages, since, groupId) {
	const db = getGroupDb(groupId);
	try {
		const newMessages = db.all(`SELECT * FROM messages_binary
           WHERE timestamp > ?
           ORDER BY timestamp`, [since]);
		return {
			trie: addMessages(db, messages),
			newMessages: newMessages.map((msg) => create(MessageEnvelopeSchema, {
				timestamp: msg.timestamp,
				isEncrypted: msg.is_encrypted === 1,
				content: msg.content
			}))
		};
	} catch (e) {
		if (e.rejectedReason) return { error: e.rejectedReason };
		throw e;
	} finally {
		db.close();
	}
}
//#endregion
//#region src/util/atomic-write.ts
var tempFileCounter = 0;
async function resolveTarget(filepath) {
	try {
		return await fs$1.realpath(filepath);
	} catch (err) {
		if (err.code !== "ENOENT") throw err;
	}
	const link = await fs$1.readlink(filepath).catch(() => null);
	if (link === null) return filepath;
	return resolveTarget(isAbsolute(link) ? link : dirname(filepath) + sep + link);
}
async function atomicWriteFile(filepath, contents) {
	const target = await resolveTarget(filepath);
	const tmpPath = `${target}.${process.pid}.${tempFileCounter++}.tmp`;
	const mode = await fs$1.stat(target).then((stats) => stats.mode & 511, () => void 0);
	try {
		await fs$1.writeFile(tmpPath, contents, {
			flush: true,
			mode
		});
		if (mode !== void 0) await fs$1.chmod(tmpPath, mode).catch(() => void 0);
		await fs$1.rename(tmpPath, target);
	} catch (err) {
		await fs$1.rm(tmpPath, { force: true }).catch(() => void 0);
		throw err;
	}
}
//#endregion
//#region src/app-sync.ts
var app$1 = express();
app$1.use((req, res, next) => {
	if (!(req.method === "GET" && [
		"/list-user-files",
		"/get-user-file-info",
		"/download-user-file"
	].includes(req.path) || req.method === "POST" && ["/sync", "/user-get-key"].includes(req.path))) return validateSessionMiddleware(req, res, next);
	const session = validateBudgetSession(req, res);
	if (session) {
		res.locals = session;
		next();
	}
});
app$1.use(errorMiddleware);
app$1.use(requestLoggerMiddleware);
app$1.use(express.raw({
	type: "application/actual-sync",
	limit: `${configSchema.get("upload.fileSizeSyncLimitMB")}mb`
}));
app$1.use(express.raw({
	type: "application/encrypted-file",
	limit: `${configSchema.get("upload.syncEncryptedFileSizeLimitMB")}mb`
}));
app$1.use(express.json({ limit: `${configSchema.get("upload.fileSizeLimitMB")}mb` }));
var OK_RESPONSE = { status: "ok" };
function boolToInt(deleted) {
	return deleted ? 1 : 0;
}
function generateGroupId() {
	const id = v4();
	if (!isValidGroupId(id)) throw new TypeError("UUID format no longer matches expected format");
	return id;
}
function extractSingleHeader(req, res, key) {
	const value = req.headers[key];
	if (!value) return null;
	if (typeof value !== "string") {
		res.status(400).send("Duplicate headers encountered for key " + key);
		return null;
	}
	return value;
}
var verifyFileExists = (fileId, filesService, res, errorObject) => {
	if (res.locals.apiKeyFileIds && !res.locals.apiKeyFileIds.includes(fileId)) {
		res.status(403).send("file-access-not-allowed");
		return;
	}
	if (typeof fileId !== "string" || !isValidFileId(fileId)) {
		res.status(400).send("invalid fileId");
		return;
	}
	try {
		return filesService.get(fileId);
	} catch (e) {
		if (e instanceof FileNotFound) {
			res.status(400).send(errorObject);
			return;
		}
		throw e;
	}
};
function requireFileOwner(file, userId) {
	const isOwner = file.owner === userId;
	const isServerAdmin = isAdmin(userId);
	if (isOwner || isServerAdmin) return null;
	return "file-access-not-allowed";
}
function requireFileAccess(file, userId) {
	if (requireFileOwner(file, userId) === null) return null;
	if (countUserAccess(file.id, userId) > 0) return null;
	return "file-access-not-allowed";
}
app$1.post("/sync", async (req, res) => {
	let requestPb;
	try {
		requestPb = fromBinary(SyncRequestSchema, req.body);
	} catch (e) {
		console.log("Error parsing sync request", e);
		res.status(500);
		res.send({
			status: "error",
			reason: "internal-error"
		});
		return;
	}
	const fileId = requestPb.fileId || null;
	const groupId = requestPb.groupId || null;
	const keyId = requestPb.keyId || null;
	const since = requestPb.since || null;
	const messages = requestPb.messages;
	if (!since) {
		res.status(422).send({
			details: "since-required",
			reason: "unprocessable-entity",
			status: "error"
		});
		return;
	}
	const currentFile = verifyFileExists(fileId, new FilesService(getAccountDb()), res, "file-not-found");
	if (!currentFile) return;
	const fileAccessError = requireFileAccess(currentFile, res.locals.user_id);
	if (fileAccessError) {
		res.status(403);
		res.send(fileAccessError);
		return;
	}
	const errorMessage = validateSyncedFile(groupId, keyId, currentFile);
	if (errorMessage) {
		res.status(400);
		res.send(errorMessage);
		return;
	}
	const result = sync(messages, since, groupId);
	if (result.error) {
		res.status(400).send(result.error);
		return;
	}
	const { trie, newMessages } = result;
	const responsePb = create(SyncResponseSchema, {
		merkle: JSON.stringify(trie),
		messages: newMessages
	});
	res.set("Content-Type", "application/actual-sync");
	res.set("X-ACTUAL-SYNC-METHOD", "simple");
	res.send(Buffer$1.from(toBinary(SyncResponseSchema, responsePb)));
});
app$1.post("/user-get-key", (req, res) => {
	if (!res.locals) return;
	const { fileId } = req.body || {};
	const file = verifyFileExists(fileId, new FilesService(getAccountDb()), res, "file-not-found");
	if (!file) return;
	const fileAccessError = requireFileAccess(file, res.locals.user_id);
	if (fileAccessError) {
		res.status(403);
		res.send(fileAccessError);
		return;
	}
	res.send({
		status: "ok",
		data: {
			id: file.encryptKeyId,
			salt: file.encryptSalt,
			test: file.encryptTest
		}
	});
});
app$1.post("/user-create-key", (req, res) => {
	const { fileId, keyId, keySalt, testContent } = req.body || {};
	const filesService = new FilesService(getAccountDb());
	const file = verifyFileExists(fileId, filesService, res, "file-not-found");
	if (!file) return;
	const fileAccessError = requireFileOwner(file, res.locals.user_id);
	if (fileAccessError) {
		res.status(403);
		res.send(fileAccessError);
		return;
	}
	filesService.update(file.id, new FileUpdate({
		encryptSalt: keySalt,
		encryptKeyId: keyId,
		encryptTest: testContent
	}));
	res.send(OK_RESPONSE);
});
app$1.post("/reset-user-file", async (req, res) => {
	const { fileId } = req.body || {};
	const filesService = new FilesService(getAccountDb());
	const file = verifyFileExists(fileId, filesService, res, "User or file not found");
	if (!file) return;
	const fileAccessError = requireFileOwner(file, res.locals.user_id);
	if (fileAccessError) {
		res.status(403);
		res.send(fileAccessError);
		return;
	}
	const groupId = file.groupId;
	filesService.update(file.id, new FileUpdate({ groupId: null }));
	if (groupId) try {
		await fs$1.unlink(getPathForGroupFile(groupId));
	} catch {
		console.log(`Unable to delete sync data for group "${groupId}"`);
	}
	res.send(OK_RESPONSE);
});
app$1.post("/upload-user-file", async (req, res) => {
	if (typeof req.headers["x-actual-name"] !== "string") {
		res.status(400).send("single x-actual-name is required");
		return;
	}
	const name = decodeURIComponent(req.headers["x-actual-name"]);
	const fileId = req.headers["x-actual-file-id"];
	if (!fileId || typeof fileId !== "string") {
		res.status(400).send("fileId is required");
		return;
	}
	if (!isValidFileId(fileId)) {
		res.status(400).send("invalid fileId");
		return;
	}
	const groupIdHeader = req.headers["x-actual-group-id"];
	const encryptMeta = extractSingleHeader(req, res, "x-actual-encrypt-meta");
	if (res.headersSent) return;
	const syncFormatVersion = extractSingleHeader(req, res, "x-actual-format");
	if (res.headersSent) return;
	let groupId = null;
	if (groupIdHeader !== void 0) {
		if (typeof groupIdHeader !== "string" || !isValidGroupId(groupIdHeader)) {
			res.status(400).send("invalid groupId");
			return;
		}
		groupId = groupIdHeader;
	}
	const keyId = encryptMeta && typeof encryptMeta === "string" ? JSON.parse(encryptMeta).keyId : null;
	const filesService = new FilesService(getAccountDb());
	let currentFile;
	try {
		currentFile = filesService.get(fileId);
	} catch (e) {
		if (e instanceof FileNotFound) currentFile = null;
		else throw e;
	}
	const fileAccessError = currentFile ? requireFileAccess(currentFile, res.locals.user_id) : null;
	if (fileAccessError) {
		res.status(403);
		res.send(fileAccessError);
		return;
	}
	const errorMessage = validateUploadedFile(groupId, keyId, currentFile);
	if (errorMessage) {
		res.status(400).send(errorMessage);
		return;
	}
	try {
		await atomicWriteFile(getPathForUserFile(fileId), req.body);
	} catch (err) {
		console.log("Error writing file", err);
		res.status(500).send({ status: "error" });
		return;
	}
	if (!currentFile) {
		const newGroupId = generateGroupId();
		groupId = newGroupId;
		filesService.set(new File({
			id: fileId,
			groupId: newGroupId,
			syncVersion: syncFormatVersion,
			name,
			encryptMeta,
			owner: res.locals.user_id || (() => {
				throw new Error("User ID is required for file creation");
			})()
		}));
		res.send({
			status: "ok",
			groupId
		});
		return;
	}
	if (!groupId) {
		const newGroupId = generateGroupId();
		groupId = newGroupId;
		filesService.update(fileId, new FileUpdate({ groupId: newGroupId }));
	}
	filesService.update(fileId, new FileUpdate({
		syncVersion: syncFormatVersion,
		encryptMeta,
		name
	}));
	res.send({
		status: "ok",
		groupId
	});
});
app$1.get("/download-user-file", async (req, res) => {
	const fileId = req.headers["x-actual-file-id"];
	if (typeof fileId !== "string") {
		res.status(400).send("Single file ID is required");
		return;
	}
	if (!isValidFileId(fileId)) {
		res.status(400).send("invalid fileId");
		return;
	}
	const file = verifyFileExists(fileId, new FilesService(getAccountDb()), res, "User or file not found");
	if (!file) return;
	const fileAccessError = requireFileAccess(file, res.locals.user_id);
	if (fileAccessError) {
		res.status(403);
		res.send(fileAccessError);
		return;
	}
	const path = getPathForUserFile(fileId);
	if (!path.startsWith(resolve(configSchema.get("userFiles")))) {
		res.status(403).send("Access denied");
		return;
	}
	res.setHeader("Content-Disposition", `attachment;filename=${fileId}`);
	res.sendFile(path, { dotfiles: "allow" });
});
app$1.post("/update-user-filename", (req, res) => {
	const { fileId, name } = req.body || {};
	const filesService = new FilesService(getAccountDb());
	const file = verifyFileExists(fileId, filesService, res, "file-not-found");
	if (!file) return;
	const fileAccessError = requireFileAccess(file, res.locals.user_id);
	if (fileAccessError) {
		res.status(403);
		res.send(fileAccessError);
		return;
	}
	filesService.update(file.id, new FileUpdate({ name }));
	res.send(OK_RESPONSE);
});
app$1.get("/list-user-files", (req, res) => {
	const fileService = new FilesService(getAccountDb());
	const rows = fileService.find({ userId: res.locals.user_id }).filter((row) => !res.locals.apiKeyFileIds || res.locals.apiKeyFileIds.includes(row.id));
	res.send({
		status: "ok",
		data: rows.map((row) => ({
			deleted: boolToInt(row.deleted),
			fileId: row.id,
			groupId: row.groupId,
			name: row.name,
			encryptKeyId: row.encryptKeyId,
			owner: row.owner,
			usersWithAccess: fileService.findUsersWithAccess(row.id).map((access) => ({
				...access,
				owner: access.userId === row.owner
			}))
		}))
	});
});
app$1.get("/get-user-file-info", (req, res) => {
	const fileId = req.headers["x-actual-file-id"];
	const fileService = new FilesService(getAccountDb());
	const file = verifyFileExists(fileId, fileService, res, {
		status: "error",
		reason: "file-not-found"
	});
	if (!file) return;
	const fileAccessError = requireFileAccess(file, res.locals.user_id);
	if (fileAccessError) {
		res.status(403);
		res.send(fileAccessError);
		return;
	}
	res.send({
		status: "ok",
		data: {
			deleted: boolToInt(file.deleted),
			fileId: file.id,
			groupId: file.groupId,
			name: file.name,
			encryptMeta: file.encryptMeta ? JSON.parse(file.encryptMeta) : null,
			usersWithAccess: fileService.findUsersWithAccess(file.id).map((access) => ({
				...access,
				owner: access.userId === file.owner
			}))
		}
	});
});
app$1.post("/delete-user-file", (req, res) => {
	const { fileId } = req.body || {};
	if (!fileId) {
		res.status(422).send({
			details: "fileId-required",
			reason: "unprocessable-entity",
			status: "error"
		});
		return;
	}
	const accountDb = getAccountDb();
	const filesService = new FilesService(accountDb);
	const file = verifyFileExists(fileId, filesService, res, "file-not-found");
	if (!file) return;
	const fileAccessError = requireFileOwner(file, res.locals.user_id);
	if (fileAccessError) {
		res.status(403);
		res.send(fileAccessError);
		return;
	}
	accountDb.transaction(() => {
		filesService.update(file.id, new FileUpdate({ deleted: true }));
		for (const name of Object.values(SecretName)) secretsService.reset(name, file.id);
	});
	res.send(OK_RESPONSE);
});
//#endregion
//#region src/util/server-listen.ts
function listen(server, port, hostname) {
	return new Promise((resolve, reject) => {
		server.once("error", reject);
		server.listen(port, hostname === "::" ? void 0 : hostname, () => {
			server.off("error", reject);
			const address = server.address();
			resolve(address && typeof address === "object" ? address.address : hostname);
		});
	});
}
//#endregion
//#region src/app.ts
var debugSensitive = createDebug("actual-sensitive:server");
var app = express();
process.on("unhandledRejection", (reason) => {
	console.log("Unhandled rejection");
	debugSensitive("Unhandled rejection: %O", reason);
});
app.disable("x-powered-by");
app.use(cors());
app.set("trust proxy", configSchema.get("trustedProxies"));
if (process.env.NODE_ENV !== "development") app.use(rateLimit({
	windowMs: 6e4,
	max: 500,
	legacyHeaders: false,
	standardHeaders: true
}));
app.use(express.json({ limit: `${configSchema.get("upload.fileSizeLimitMB")}mb` }));
app.use(express.raw({
	type: "application/actual-sync",
	limit: `${configSchema.get("upload.fileSizeSyncLimitMB")}mb`
}));
app.use(express.raw({
	type: "application/encrypted-file",
	limit: `${configSchema.get("upload.syncEncryptedFileSizeLimitMB")}mb`
}));
app.use("/sync", app$1);
app.use("/account", app$12);
app.use("/api-keys", app$9);
app.use("/gocardless", app$6);
app.use("/simplefin", app$2);
app.use("/pluggyai", app$4);
app.use("/akahu", app$10);
app.use("/enablebanking", app$7);
app.use("/secret", app$3);
if (configSchema.get("corsProxy.enabled")) app.use("/cors-proxy", app$8);
app.use("/admin", app$11);
app.use("/openid", app$5);
app.get("/mode", (req, res) => {
	res.send(configSchema.get("mode"));
});
app.get("/info", (_req, res) => {
	function findPackageJson(startDir) {
		let currentPath = startDir;
		let directoriesSearched = 0;
		const pathRoot = resolve(currentPath, "/");
		try {
			while (currentPath !== pathRoot && directoriesSearched < 5) {
				const packageJsonPath = resolve(currentPath, "package.json");
				if (fs.existsSync(packageJsonPath)) {
					const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf-8"));
					if (packageJson.name === "@actual-app/sync-server") return packageJson;
				}
				currentPath = resolve(join(currentPath, ".."));
				directoriesSearched++;
			}
		} catch (error) {
			console.error("Error while searching for package.json:", error);
		}
		return null;
	}
	const packageJson = findPackageJson(resolve(fileURLToPath(import.meta.url), "../"));
	res.status(200).json({ build: {
		name: packageJson?.name,
		description: packageJson?.description,
		version: packageJson?.version
	} });
});
app.get("/health", (_req, res) => {
	res.status(200).json({ status: "UP" });
});
app.get("/metrics", (_req, res) => {
	res.status(200).json({
		mem: process.memoryUsage(),
		uptime: process.uptime()
	});
});
var isDev = process.env.NODE_ENV === "development";
var scriptSrc = isDev ? "'self' 'unsafe-inline' 'unsafe-eval' blob:" : "'self' 'unsafe-eval' blob:";
var connectSrc = isDev ? "'self' ws: wss: http: https:" : "http: https:";
var csp = [
	"default-src 'self' blob:",
	"img-src 'self' blob: data:",
	`script-src ${scriptSrc}`,
	"style-src 'self' 'unsafe-inline'",
	"font-src 'self' data:",
	`connect-src ${connectSrc}`
].join("; ");
app.use((req, res, next) => {
	res.set("Cross-Origin-Opener-Policy", "same-origin");
	res.set("Cross-Origin-Embedder-Policy", "require-corp");
	res.set("Content-Security-Policy", csp);
	next();
});
if (isDev) {
	console.log("Running in development mode - Proxying frontend routes to React Dev Server");
	const httpProxyMiddleware = await import("http-proxy-middleware");
	app.use(httpProxyMiddleware.createProxyMiddleware({
		target: "http://localhost:3001",
		changeOrigin: true,
		ws: true
	}));
} else {
	console.log("Running in production mode - Serving static React app");
	app.use(express.static(configSchema.get("webRoot"), { index: false }));
	app.get("/{*splat}", (req, res) => res.sendFile("index.html", { root: configSchema.get("webRoot") }));
}
function parseHTTPSConfig(value) {
	if (value.startsWith("-----BEGIN")) return value.replace(/\\n/g, "\n");
	return fs.readFileSync(value);
}
function sendServerStartedMessage(address) {
	process.parentPort?.postMessage({ type: "server-started" });
	console.log("Listening on " + address + ":" + configSchema.get("port") + "...");
}
async function run() {
	const portVal = configSchema.get("port");
	const port = typeof portVal === "string" ? parseInt(portVal) : portVal;
	const hostname = configSchema.get("hostname");
	const openIdConfig = configSchema?.getProperties()?.openId;
	if (openIdConfig?.discoveryURL || openIdConfig?.issuer?.authorization_endpoint) {
		console.log("OpenID configuration found. Preparing server to use it");
		try {
			const result = await bootstrap({ openId: openIdConfig }, true);
			if ("error" in result && result.error) console.log(result.error);
			else console.log("OpenID configured!");
		} catch (err) {
			console.error(err);
		}
	}
	if (configSchema.get("https.key") && configSchema.get("https.cert")) {
		const https = await import("node:https");
		const httpsOptions = {
			...configSchema.get("https"),
			key: parseHTTPSConfig(configSchema.get("https.key")),
			cert: parseHTTPSConfig(configSchema.get("https.cert"))
		};
		sendServerStartedMessage(await listen(https.createServer(httpsOptions, app), port, hostname));
	} else sendServerStartedMessage(await listen((await import("node:http")).createServer(app), port, hostname));
}
//#endregion
export { run };

//# sourceMappingURL=app-CLHtiAzx.js.map