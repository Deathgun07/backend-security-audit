const { execSync } = require("child_process");

afterAll(() => execSync("rm -rf " + process.env.TMP_DIR));
