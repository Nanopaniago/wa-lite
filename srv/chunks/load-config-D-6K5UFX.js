import path from "node:path";
import { createRequire } from "module";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import convict from "convict";
import createDebug from "debug";
import dns from "dns";
import { promisify } from "util";
import ipaddr from "ipaddr.js";
import { EnvHttpProxyAgent } from "undici";
//#region src/config-file-env.ts
/**
* Reads the value of a `<VAR>_FILE` environment variable, returning the
* contents of the file it points at and throwing if the file is not accessible.
*/
function readFileEnv(fileEnvVar, env = process.env) {
	const filePath = env[fileEnvVar];
	if (filePath === void 0) return void 0;
	try {
		return fs.readFileSync(filePath, "utf8").trim();
	} catch (error) {
		const reason = error instanceof Error ? error.message : String(error);
		throw new Error(`Could not read ${fileEnvVar} from '${filePath}': ${reason}`);
	}
}
/**
* Applies a `<VAR>_FILE` override onto a convict setting, returning whether
* one was applied.
*/
function applyFileEnv(config, fileEnvVar, path, env = process.env) {
	const value = readFileEnv(fileEnvVar, env);
	if (value === void 0) return false;
	config.set(path, value);
	return true;
}
//#endregion
//#region src/util/ssrf.ts
var dnsLookup = promisify(dns.lookup);
var NAT64_PREFIX = ipaddr.IPv6.parseCIDR("64:ff9b::/96");
var PRIVATE_IP_RANGES = [
	"private",
	"loopback",
	"uniqueLocal",
	"carrierGradeNat"
];
/**
* Return true if the given address is a literal IP in one of the blocked
* ranges (link-local/reserved/etc, plus private ranges unless
* allowPrivateNetwork is set). Non-IP strings (e.g. hostnames) return false,
* so callers can pass a URL hostname directly.
*/
function isBlockedIp(address, { allowPrivateNetwork = false, allowedNetworks = [] } = {}) {
	if (!ipaddr.isValid(address)) return false;
	const parsed = ipaddr.process(address);
	if (parsed instanceof ipaddr.IPv6 && parsed.match(NAT64_PREFIX)) return ipaddr.fromByteArray(parsed.toByteArray().slice(12)).range() !== "unicast";
	const range = parsed.range();
	return range !== "unicast" && !(PRIVATE_IP_RANGES.includes(range) && (allowPrivateNetwork || allowedNetworks.some((network) => {
		const [subnet, prefix] = parseAllowedNetwork(network);
		return parsed.kind() === subnet.kind() && parsed.match(subnet, prefix);
	})));
}
/**
* Validate that a URL is safe to make a server-side request to, guarding
* against SSRF. Only http(s) URLs are permitted, and the hostname is resolved
* via DNS so that hostnames pointing at private/local/link-local addresses are
* rejected as well as literal IPs. Throws if the URL is not allowed.
*
* Use allowedNetworks for specific private IPs or CIDR ranges; the
* other address classes (including transition, multicast and link-local) remain blocked
* regardless.
*/
async function assertUrlAllowed(targetUrl, options = {}) {
	let url;
	try {
		url = new URL(targetUrl);
	} catch {
		throw new Error("Invalid URL");
	}
	if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error(`Blocked request to disallowed protocol: ${url.protocol}`);
	const hostname = url.hostname.replace(/^\[|\]$/g, "");
	if (ipaddr.isValid(hostname)) {
		if (isBlockedIp(hostname, options)) throw new Error(`Blocked request to private/local IP: ${hostname}`);
		return;
	}
	let addresses;
	try {
		addresses = await dnsLookup(hostname, { all: true });
	} catch {
		throw new Error(`Unable to resolve host: ${hostname}`);
	}
	if (addresses.length === 0) throw new Error(`Unable to resolve host: ${hostname}`);
	for (const { address } of addresses) if (isBlockedIp(address, options)) throw new Error(`Blocked request to host resolving to private/local IP: ${hostname} (${address})`);
}
function parseAllowedNetwork(network) {
	if (network.includes("/")) return ipaddr.parseCIDR(network);
	const address = ipaddr.parse(network);
	return [address, address.kind() === "ipv4" ? 32 : 128];
}
function createSsrfDispatcher(options) {
	return new EnvHttpProxyAgent({ connect: { lookup(hostname, lookupOptions, callback) {
		dns.lookup(hostname, {
			...lookupOptions,
			all: true
		}, (error, addresses) => {
			if (error) callback(error, []);
			else if (!addresses.length || addresses.some(({ address }) => isBlockedIp(address, options))) callback(/* @__PURE__ */ new Error("Blocked request to private/local IP"), []);
			else if (lookupOptions.all) callback(null, addresses);
			else callback(null, addresses[0].address, addresses[0].family);
		});
	} } });
}
//#endregion
//#region src/load-config.js
var require = createRequire(import.meta.url);
var debug = createDebug("actual:config");
var debugSensitive = createDebug("actual-sensitive:config");
var __dirname = path.dirname(fileURLToPath(import.meta.url));
var projectRoot = path.dirname(__dirname).replace(/[\\/]build$/, "");
var defaultDataDir = process.env.ACTUAL_DATA_DIR ? process.env.ACTUAL_DATA_DIR : fs.existsSync("/data") ? "/data" : projectRoot;
debug(`Project root: '${projectRoot}'`);
var actualAppWebBuildPath = path.join(path.dirname(require.resolve("@actual-app/web/package.json")), "build");
debug(`Actual web build path: '${actualAppWebBuildPath}'`);
convict.addFormat({
	name: "tokenExpiration",
	validate(val) {
		if (val === "never" || val === "openid-provider") return;
		if (typeof val === "number" && Number.isFinite(val) && val >= 0) return;
		if (typeof val === "string") {
			const numVal = Number(val);
			if (Number.isFinite(numVal) && numVal >= 0) return;
		}
		throw new Error(`Invalid token_expiration value: ${val}: value was "${val}"`);
	},
	coerce(val) {
		if (val === "never" || val === "openid-provider") return val;
		if (typeof val === "number") return val;
		if (typeof val === "string") {
			const numVal = Number(val);
			if (Number.isFinite(numVal) && numVal >= 0) return numVal;
		}
		return val;
	}
});
convict.addFormat({
	name: "ipNetworks",
	validate(values) {
		if (!Array.isArray(values)) throw new Error("Expected an array of IP addresses or CIDR ranges");
		values.forEach(parseAllowedNetwork);
	},
	coerce: (value) => value.split(",").map((entry) => entry.trim()).filter(Boolean)
});
var configSchema = convict({
	env: {
		doc: "The application environment.",
		format: [
			"production",
			"development",
			"test"
		],
		default: "development",
		env: "NODE_ENV"
	},
	mode: {
		doc: "Application mode.",
		format: ["test", "development"],
		default: process.env.NODE_ENV === "test" ? "test" : "development"
	},
	projectRoot: {
		doc: "Project root directory.",
		format: String,
		default: projectRoot
	},
	dataDir: {
		doc: "Default data directory.",
		format: String,
		default: process.env.NODE_ENV === "test" ? projectRoot : defaultDataDir,
		env: "ACTUAL_DATA_DIR"
	},
	port: {
		doc: "Port to run the server on.",
		format: "port",
		default: process.env.PORT ? process.env.PORT : 5006,
		env: "ACTUAL_PORT"
	},
	hostname: {
		doc: "Server hostname.",
		format: String,
		default: "::",
		env: "ACTUAL_HOSTNAME"
	},
	serverFiles: {
		doc: "Path to server files.",
		format: String,
		default: process.env.NODE_ENV === "test" ? path.join(projectRoot, "test-server-files") : path.join(defaultDataDir, "server-files"),
		env: "ACTUAL_SERVER_FILES"
	},
	userFiles: {
		doc: "Path to user files.",
		format: String,
		default: process.env.NODE_ENV === "test" ? path.join(projectRoot, "test-user-files") : path.join(defaultDataDir, "user-files"),
		env: "ACTUAL_USER_FILES"
	},
	webRoot: {
		doc: "Web root directory.",
		format: String,
		default: actualAppWebBuildPath,
		env: "ACTUAL_WEB_ROOT"
	},
	loginMethod: {
		doc: "Authentication method.",
		format: [
			"password",
			"header",
			"openid",
			"userpass"
		],
		default: "password",
		env: "ACTUAL_LOGIN_METHOD"
	},
	allowedLoginMethods: {
		doc: "Allowed authentication methods.",
		format: Array,
		default: [
			"password",
			"header",
			"openid",
			"userpass"
		],
		env: "ACTUAL_ALLOWED_LOGIN_METHODS"
	},
	simplefinAllowedNetworks: {
		doc: "Private IP addresses or CIDR ranges that may be used as a SimpleFIN server",
		format: "ipNetworks",
		default: [],
		env: "ACTUAL_SIMPLEFIN_ALLOWED_NETWORKS"
	},
	trustedProxies: {
		doc: "List of trusted proxies.",
		format: Array,
		default: [
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"fc00::/7",
			"::1/128"
		],
		env: "ACTUAL_TRUSTED_PROXIES"
	},
	trustedAuthProxies: {
		doc: "List of trusted auth proxies.",
		format: Array,
		default: [],
		env: "ACTUAL_TRUSTED_AUTH_PROXIES"
	},
	https: {
		doc: "HTTPS configuration.",
		key: {
			doc: "HTTPS Certificate key",
			format: String,
			default: "",
			env: "ACTUAL_HTTPS_KEY"
		},
		cert: {
			doc: "HTTPS Certificate",
			format: String,
			default: "",
			env: "ACTUAL_HTTPS_CERT"
		}
	},
	upload: {
		doc: "Upload configuration.",
		fileSizeSyncLimitMB: {
			doc: "Sync file size limit (in MB)",
			format: "nat",
			default: 20,
			env: "ACTUAL_UPLOAD_FILE_SYNC_SIZE_LIMIT_MB"
		},
		syncEncryptedFileSizeLimitMB: {
			doc: "Encrypted Sync file size limit (in MB)",
			format: "nat",
			default: 50,
			env: "ACTUAL_UPLOAD_SYNC_ENCRYPTED_FILE_SYNC_SIZE_LIMIT_MB"
		},
		fileSizeLimitMB: {
			doc: "General file size limit (in MB)",
			format: "nat",
			default: 20,
			env: "ACTUAL_UPLOAD_FILE_SIZE_LIMIT_MB"
		}
	},
	openId: {
		doc: "OpenID authentication settings.",
		discoveryURL: {
			doc: "OpenID Provider discovery URL.",
			format: String,
			default: "",
			env: "ACTUAL_OPENID_DISCOVERY_URL"
		},
		issuer: {
			doc: "OpenID issuer",
			name: {
				doc: "Name of the provider",
				default: "",
				format: String,
				env: "ACTUAL_OPENID_PROVIDER_NAME"
			},
			authorization_endpoint: {
				doc: "Authorization endpoint",
				default: "",
				format: String,
				env: "ACTUAL_OPENID_AUTHORIZATION_ENDPOINT"
			},
			token_endpoint: {
				doc: "Token endpoint",
				default: "",
				format: String,
				env: "ACTUAL_OPENID_TOKEN_ENDPOINT"
			},
			userinfo_endpoint: {
				doc: "Userinfo endpoint",
				default: "",
				format: String,
				env: "ACTUAL_OPENID_USERINFO_ENDPOINT"
			}
		},
		client_id: {
			doc: "OpenID client ID.",
			format: String,
			default: "",
			env: "ACTUAL_OPENID_CLIENT_ID"
		},
		client_secret: {
			doc: "OpenID client secret.",
			format: String,
			default: "",
			env: "ACTUAL_OPENID_CLIENT_SECRET"
		},
		server_hostname: {
			doc: "OpenID server hostname.",
			format: String,
			default: "",
			env: "ACTUAL_OPENID_SERVER_HOSTNAME"
		},
		authMethod: {
			doc: "OpenID authentication method.",
			format: ["openid", "oauth2"],
			default: "openid",
			env: "ACTUAL_OPENID_AUTH_METHOD"
		}
	},
	token_expiration: {
		doc: "Token expiration time.",
		format: "tokenExpiration",
		default: "never",
		env: "ACTUAL_TOKEN_EXPIRATION"
	},
	enforceOpenId: {
		doc: "Enforce OpenID authentication.",
		format: Boolean,
		default: false,
		env: "ACTUAL_OPENID_ENFORCE"
	},
	userCreationMode: {
		doc: "Determines how users can be created.",
		format: ["manual", "login"],
		default: "manual",
		env: "ACTUAL_USER_CREATION_MODE"
	},
	github: {
		doc: "GitHub API configuration.",
		token: {
			doc: "GitHub Personal Access Token for API authentication.",
			format: String,
			default: "",
			env: "ACTUAL_GITHUB_TOKEN"
		}
	},
	corsProxy: {
		doc: "CORS proxy configuration for frontend plugins.",
		enabled: {
			doc: "Enable the CORS proxy endpoint.",
			format: Boolean,
			default: false,
			env: "ACTUAL_CORS_PROXY_ENABLED"
		}
	}
});
var configPath = null;
if (process.env.ACTUAL_CONFIG_PATH) {
	debug(`loading config from ACTUAL_CONFIG_PATH: '${process.env.ACTUAL_CONFIG_PATH}'`);
	configPath = process.env.ACTUAL_CONFIG_PATH;
} else {
	configPath = path.join(projectRoot, "config.json");
	if (!fs.existsSync(configPath)) configPath = path.join(defaultDataDir, "config.json");
	debug(`loading config from default path: '${configPath}'`);
}
if (fs.existsSync(configPath)) {
	configSchema.loadFile(configPath);
	debug(`Config loaded`);
}
for (const [fileEnvVar, settingPath] of [["ACTUAL_OPENID_CLIENT_SECRET_FILE", "openId.client_secret"], ["ACTUAL_GITHUB_TOKEN_FILE", "github.token"]]) if (applyFileEnv(configSchema, fileEnvVar, settingPath)) debug(`Loaded ${settingPath} from ${fileEnvVar}`);
debug(`Validating config`);
configSchema.validate({ allowed: "strict" });
debug(`Project root: ${configSchema.get("projectRoot")}`);
debug(`Port: ${configSchema.get("port")}`);
debug(`Hostname: ${configSchema.get("hostname")}`);
debug(`Data directory: ${configSchema.get("dataDir")}`);
debug(`Server files: ${configSchema.get("serverFiles")}`);
debug(`User files: ${configSchema.get("userFiles")}`);
debug(`Web root: ${configSchema.get("webRoot")}`);
debug(`Login method: ${configSchema.get("loginMethod")}`);
debug(`Allowed methods: ${configSchema.get("allowedLoginMethods").join(", ")}`);
debug(`CORS Proxy enabled: ${configSchema.get("corsProxy.enabled")}`);
var httpsKey = configSchema.get("https.key");
if (httpsKey) {
	debug(`HTTPS Key: ${"*".repeat(httpsKey.length)}`);
	debugSensitive(`HTTPS Key: ${httpsKey}`);
}
var httpsCert = configSchema.get("https.cert");
if (httpsCert) {
	debug(`HTTPS Cert: ${"*".repeat(httpsCert.length)}`);
	debugSensitive(`HTTPS Cert: ${httpsCert}`);
}
var githubToken = configSchema.get("github.token");
if (githubToken) {
	debug(`GitHub Token: ${"*".repeat(Math.min(githubToken.length, 20))}`);
	debugSensitive(`GitHub Token: ${githubToken}`);
}
//#endregion
export { isBlockedIp as i, assertUrlAllowed as n, createSsrfDispatcher as r, configSchema as t };

//# sourceMappingURL=load-config-D-6K5UFX.js.map