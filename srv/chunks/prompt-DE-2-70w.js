import { cursorTo } from "node:readline";
//#region src/util/prompt.ts
async function promptPassword() {
	const password = await askForPassword("Enter a password, then press enter: ");
	if (password === "") {
		console.log("Password cannot be empty.");
		return promptPassword();
	}
	if (password !== await askForPassword("Enter the password again, then press enter: ")) {
		console.log("Passwords do not match.");
		return promptPassword();
	}
	return password;
}
async function askForPassword(prompt) {
	let dataListener = () => null;
	let endListener = () => null;
	const answer = await new Promise((resolve) => {
		let result = "";
		process.stdout.write(prompt);
		process.stdin.setRawMode(true);
		process.stdin.resume();
		dataListener = (key) => {
			switch (key[0]) {
				case 3:
					process.exit();
					break;
				case 13:
					process.stdin.setRawMode(false);
					process.stdin.pause();
					resolve(result);
					break;
				case 127:
				case 8:
					if (result) {
						result = result.slice(0, -1);
						cursorTo(process.stdout, prompt.length + result.length);
						process.stdout.write(" ");
						cursorTo(process.stdout, prompt.length + result.length);
					}
					break;
				default:
					result += key;
					process.stdout.write("*");
			}
		};
		process.stdin.on("data", dataListener);
		endListener = () => resolve(result);
		process.stdin.on("end", endListener);
	});
	process.stdin.off("data", dataListener);
	process.stdin.off("end", endListener);
	process.stdout.write("\n");
	return answer;
}
//#endregion
export { promptPassword as t };

//# sourceMappingURL=prompt-DE-2-70w.js.map