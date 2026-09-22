// FIXTURE — deliberately vulnerable. Every pattern here exists so
// verify-rulepack.sh can prove the FORCE Code Audit rules fire. The AWS key is
// the AWS documentation example value, not a real credential. Never imported,
// never built, excluded from the SAST gate via .semgrepignore.

import crypto from "crypto";
import child_process from "child_process";

const apiKey = "AKIAIOSFODNN7EXAMPLE";
const dbPassword = "hunter2";
const secretName = "force/github/token";

const h = crypto.createHash("md5").update("x").digest("hex");
const agent = { rejectUnauthorized: false };
const sessionToken = Math.random();

function run(userInput: string) {
  child_process.exec(userInput);
}

console.log("value", password);
const endpoint = "https://s3.us-east-1.amazonaws.com/cui-bucket";

// eslint-disable-next-line security/detect-object-injection
const x = obj[key];

export async function POST(req: Request) {
  return Response.json({ ok: true });
}
