// Writes a short Markdown test and coverage summary for the GitHub Actions job page.
import { readFileSync, appendFileSync, existsSync } from "node:fs";

const out = process.env.GITHUB_STEP_SUMMARY;
const lines = ["## Test results", ""];
if (existsSync("reports/junit.xml")) {
  const xml = readFileSync("reports/junit.xml", "utf8");
  const attr = (name) => Number((xml.match(new RegExp(`<testsuites[^>]*\\b${name}="(\\d+)"`)) ?? [])[1] ?? 0);
  const tests = attr("tests"), failures = attr("failures"), errors = attr("errors"), skipped = attr("skipped");
  lines.push(`| Tests | Passed | Failed | Skipped |`, `|---|---|---|---|`);
  lines.push(`| ${tests} | ${tests - failures - errors - skipped} | ${failures + errors} | ${skipped} |`, "");
}
if (existsSync("reports/coverage/coverage-summary.json")) {
  const t = JSON.parse(readFileSync("reports/coverage/coverage-summary.json", "utf8")).total;
  lines.push("| Coverage | Lines | Branches | Functions |", "|---|---|---|---|");
  lines.push(`| src/ | ${t.lines.pct}% | ${t.branches.pct}% | ${t.functions.pct}% |`);
}
const md = lines.join("\n") + "\n";
if (out) appendFileSync(out, md);
else process.stdout.write(md);
