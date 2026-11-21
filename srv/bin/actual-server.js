#!/usr/bin/env node
import { resolve } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { parseArgs } from "node:util";
//#region bin/actual-server.js
var args = process.argv;
var { values } = parseArgs({
	args,
	options: {
		help: {
			type: "boolean",
			short: "h"
		},
		version: {
			type: "boolean",
			short: "v"
		},
		"reset-password": { type: "boolean" },
		config: { type: "string" }
	},
	allowPositionals: true
});
if (values.help) {
	console.log([
		"usage: actual-server [options]",
		"",
		"options:",
		"  --config           Path to config file",
		"",
		"  -h --help          Print this list and exit.",
		"  -v --version       Print the version and exit.",
		"",
		"Examples:",
		"",
		"Runs actual-server with default configuration",
		"  actual-server",
		"",
		"Runs actual-server with custom configuration",
		"  actual-server --config ./config.json"
	].join("\n"));
	process.exit();
}
if (values.version) {
	console.log("v26.11.0");
	process.exit();
}
var setupDataDir = (dataDir) => {
	if (process.env.ACTUAL_DATA_DIR) return;
	if (dataDir) process.env.ACTUAL_DATA_DIR = dataDir;
	else {
		if (existsSync("./data")) {
			console.info("Found existing data directory");
			process.env.ACTUAL_DATA_DIR = resolve("./data");
		} else {
			console.info("Using default data directory. You can specify a custom config with --config");
			process.env.ACTUAL_DATA_DIR = resolve("./");
		}
		console.info(`Data directory: ${process.env.ACTUAL_DATA_DIR}`);
	}
};
if (values.config) {
	if (!existsSync(values.config)) {
		console.log(`Please specify a valid config path. The path ${String(values.config)} does not exist.`);
		process.exit();
	} else {
		console.log(`Loading config from ${String(values.config)}`);
		const configJson = JSON.parse(readFileSync(values.config, "utf-8"));
		process.env.ACTUAL_CONFIG_PATH = values.config;
		setupDataDir(configJson.dataDir);
	}
} else {
	const defaultConfigJsonFile = "./config.json";
	if (existsSync(defaultConfigJsonFile)) {
		console.info("Found config.json in the current directory");
		const configJson = JSON.parse(readFileSync(defaultConfigJsonFile, "utf-8"));
		process.env.ACTUAL_CONFIG_PATH = defaultConfigJsonFile;
		setupDataDir(configJson.dataDir);
	} else setupDataDir();
}
if (values["reset-password"]) {
	console.info("Running reset password script...");
	await import("../scripts/reset-password.js");
	process.exit();
}
import("../app.js");
//#endregion
export {};

//# sourceMappingURL=actual-server.js.map