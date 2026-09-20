import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

const REPORT_DIR = resolve("apps/api/runtime/quality/security-audit");
const JSON_REPORT = resolve(REPORT_DIR, "dependency-security-audit.json");
const MARKDOWN_REPORT = resolve(REPORT_DIR, "依赖安全审计报告.md");

// Only audit packages that are part of the current product build. Research and
// local-only material is not shipped by the application or included in this gate.
const PROJECTS = [
  {
    id: "console",
    name: "React 控制台",
    path: "apps/console",
    accepted: { low: 0, moderate: 0, high: 0, critical: 0 },
    note: "控制台依赖应保持 0 个已知漏洞。",
  },
  {
    id: "www",
    name: "官网",
    path: "apps/www",
    accepted: { low: 0, moderate: 0, high: 0, critical: 0 },
    note: "官网依赖应保持 0 个已知漏洞。",
  },
  {
    id: "docs",
    name: "文档站",
    path: "apps/docs",
    accepted: { low: 0, moderate: 0, high: 0, critical: 0 },
    note: "文档站依赖应保持 0 个已知漏洞。",
  },
];

function runAudit(project) {
  const npmCli = findNpmCli();
  const lockfileRelativePath = `${project.path}/package-lock.json`;
  const lockfilePath = resolve(lockfileRelativePath);
  const lockfileSha256 = hashFile(lockfilePath);
  const audit = runAuditCommand(npmCli, project.path);
  const { result, parsed } = audit;
  const counts = normalizeCounts(parsed?.metadata?.vulnerabilities);
  const commandError = result.error ? String(result.error) : "";
  const auditOutputValid = Boolean(parsed?.metadata?.vulnerabilities);
  const advisories = summarizeAdvisories(parsed);
  const fixPreview = runFixPreview(project, advisories.map((item) => item.package), lockfileSha256);
  const status = commandError || !auditOutputValid || !lockfileSha256
    ? "failed"
    : classifyStatus(counts, project.accepted);
  return {
    id: project.id,
    name: project.name,
    path: project.path,
    status,
    accepted_threshold: project.accepted,
    vulnerability_counts: counts,
    npm_audit_exit_code: result.status,
    npm_audit_attempt_count: audit.attempts.length,
    npm_audit_attempts: audit.attempts,
    command_error: commandError,
    audit_output_valid: auditOutputValid,
    lockfile_path: lockfileRelativePath,
    lockfile_sha256: lockfileSha256,
    note: project.note,
    advisories,
    fix_preview: fixPreview,
  };
}

function runAuditCommand(npmCli, projectPath) {
  const attempts = [];
  let result;
  let parsed;
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    result = spawnSync(
      process.execPath,
      [npmCli, "audit", "--json", "--prefix", projectPath, "--audit-level=low", "--registry=https://registry.npmjs.org"],
      {
        encoding: "utf8",
        maxBuffer: 1024 * 1024 * 20,
      },
    );
    parsed = parseAuditOutput(result.stdout, result.stderr);
    const outputValid = Boolean(parsed?.metadata?.vulnerabilities);
    attempts.push({
      attempt,
      exit_code: result.status,
      command_error: result.error ? String(result.error) : "",
      output_valid: outputValid,
      parse_error: String(parsed?.parse_error || ""),
    });
    // A valid npm audit document is authoritative even when vulnerabilities
    // make npm exit non-zero. Retry only transport/process/parse failures so a
    // real advisory can never be converted into a transient success.
    if (outputValid) break;
  }
  return { result, parsed, attempts };
}

function runFixPreview(project, packageNames, lockfileSha256Before) {
  const npmCli = findNpmCli();
  const result = spawnSync(
    process.execPath,
    [npmCli, "audit", "fix", "--dry-run", "--json", "--prefix", project.path, "--registry=https://registry.npmjs.org"],
    {
      encoding: "utf8",
      maxBuffer: 1024 * 1024 * 20,
    },
  );
  const parsed = parseAuditOutput(result.stdout, result.stderr);
  const changes = Array.isArray(parsed?.change)
    ? parsed.change
        .filter((item) => item?.from?.name && item?.to?.version)
        .map((item) => ({
          package: item.to.name,
          from: item.from.version || "unknown",
          to: item.to.version,
          path: item.to.path || item.from.path || "",
        }))
    : [];
  const installedVersions = readInstalledVersions(project, packageNames);
  const lockfileVersions = readLockfileVersions(project, packageNames);
  const lockfileSha256After = hashFile(resolve(`${project.path}/package-lock.json`));
  const lockfileMismatch = packageNames.some((name) => {
    const installed = installedVersions[name] || [];
    const locked = lockfileVersions[name] || [];
    return installed.length > 0 && locked.length > 0 && installed.some((version) => !locked.includes(version));
  });
  const status = result.error || !parsed || parsed.parse_error
    ? "unavailable"
    : changes.length
      ? "available"
      : "no-change-plan";
  return {
    status,
    npm_audit_exit_code: result.status,
    changes,
    installed_versions: installedVersions,
    lockfile_versions: lockfileVersions,
    installed_tree_lockfile_mismatch: lockfileMismatch,
    lockfile_sha256_before: lockfileSha256Before,
    lockfile_sha256_after: lockfileSha256After,
    lockfile_unchanged_after_preview: Boolean(
      lockfileSha256Before && lockfileSha256Before === lockfileSha256After,
    ),
    note: changes.length
      ? "dry-run only; package-lock.json was not changed"
      : "dry-run returned no package changes; package-lock.json was not changed",
  };
}

function readLockfileVersions(project, packageNames) {
  const lockfilePath = resolve(`${project.path}/package-lock.json`);
  if (!existsSync(lockfilePath)) return {};
  try {
    const lockfile = JSON.parse(readFileSync(lockfilePath, "utf8"));
    const packages = lockfile.packages || {};
    return Object.fromEntries(
      packageNames.map((name) => {
        const versions = Object.entries(packages)
          .filter(([path]) => path === `node_modules/${name}` || path.endsWith(`/node_modules/${name}`))
          .map(([, value]) => value?.version)
          .filter(Boolean);
        return [name, [...new Set(versions)]];
      }),
    );
  } catch {
    return {};
  }
}

function readInstalledVersions(project, packageNames) {
  if (!packageNames.length) return {};
  const npmCli = findNpmCli();
  const result = spawnSync(
    process.execPath,
    [npmCli, "ls", "--json", "--all", "--prefix", project.path],
    { encoding: "utf8", maxBuffer: 1024 * 1024 * 20 },
  );
  const parsed = parseAuditOutput(result.stdout, result.stderr);
  if (!parsed || parsed.parse_error) return {};
  const wanted = new Set(packageNames);
  const versions = Object.fromEntries(packageNames.map((name) => [name, []]));
  function visit(node, nameHint = "") {
    if (!node || typeof node !== "object") return;
    const name = node.name || nameHint;
    if (wanted.has(name) && node.version && !versions[name].includes(node.version)) {
      versions[name].push(node.version);
    }
    for (const [childName, child] of Object.entries(node.dependencies || {})) visit(child, childName);
  }
  visit(parsed);
  return versions;
}

function hashFile(filePath) {
  if (!existsSync(filePath)) return "";
  return createHash("sha256").update(readFileSync(filePath)).digest("hex");
}

function findNpmCli() {
  const candidates = [
    process.env.npm_execpath,
    process.env.APPDATA ? resolve(process.env.APPDATA, "npm/node_modules/npm/bin/npm-cli.js") : "",
    resolve(dirname(process.execPath), "node_modules/npm/bin/npm-cli.js"),
    resolve(dirname(process.execPath), "../node_modules/npm/bin/npm-cli.js"),
  ].filter(Boolean);
  const npmCli = candidates.find((candidate) => existsSync(candidate));
  if (!npmCli) {
    throw new Error("Unable to locate npm-cli.js. Run this command through npm or install npm with Node.js.");
  }
  return npmCli;
}

function parseAuditOutput(stdout, stderr) {
  const text = stdout?.trim() || stderr?.trim() || "";
  if (!text) {
    return {};
  }
  try {
    return JSON.parse(text);
  } catch {
    return {
      parse_error: "npm audit did not return JSON output",
      raw_output_preview: text.slice(0, 2000),
    };
  }
}

function normalizeCounts(raw = {}) {
  const info = Number(raw.info || 0);
  const low = Number(raw.low || 0);
  const moderate = Number(raw.moderate || 0);
  const high = Number(raw.high || 0);
  const critical = Number(raw.critical || 0);
  const total = Number(raw.total ?? info + low + moderate + high + critical);
  return { info, low, moderate, high, critical, total };
}

function classifyStatus(counts, accepted) {
  if (counts.critical > accepted.critical || counts.high > accepted.high) {
    return "failed";
  }
  if (counts.moderate > accepted.moderate || counts.low > accepted.low) {
    return "failed";
  }
  if (counts.total === 0) {
    return "passed";
  }
  return "accepted-residual";
}

function summarizeAdvisories(parsed) {
  const vulnerabilities = parsed?.vulnerabilities;
  if (!vulnerabilities || typeof vulnerabilities !== "object") {
    return [];
  }
  return Object.entries(vulnerabilities)
    .slice(0, 20)
    .map(([name, value]) => ({
      package: name,
      severity: value?.severity || "unknown",
      via: Array.isArray(value?.via) ? value.via.map((item) => (typeof item === "string" ? item : item?.title || item?.name || "advisory")) : [],
      fix_available: value?.fixAvailable ?? false,
    }));
}

function buildMarkdown(report) {
  const lines = [
    "# 依赖安全审计报告",
    "",
    `生成时间：${report.generated_at}`,
    `总体状态：\`${report.status}\``,
    "",
    "## 结论",
    "",
    "| 项目 | 状态 | low | moderate | high | critical | 说明 |",
    "|---|---|---:|---:|---:|---:|---|",
  ];
  for (const item of report.projects) {
    const counts = item.vulnerability_counts;
    lines.push(
      `| ${item.name} | \`${item.status}\` | ${counts.low} | ${counts.moderate} | ${counts.high} | ${counts.critical} | ${item.command_error || item.note} |`,
    );
  }
  lines.push("", "## 修复预览", "", "| 项目 | 包 | 当前版本 | 目标版本 | 状态 | 锁文件 |", "|---|---|---|---|---|---|");
  for (const item of report.projects) {
    const preview = item.fix_preview || {};
    if (!preview.changes?.length) {
      lines.push(`| ${item.name} | — | — | — | ${preview.status || "unavailable"} | ${preview.lockfile_unchanged_after_preview ? "unchanged" : "check"} |`);
      continue;
    }
    for (const change of preview.changes) {
      lines.push(`| ${item.name} | ${change.package} | ${change.from} | ${change.to} | ${preview.status} | ${preview.lockfile_unchanged_after_preview ? "unchanged" : "check"} |`);
    }
  }
  lines.push("", "当前安装树观察（仅供定位，不替代锁文件审计）", "", "| 项目 | 包 | package-lock 版本 | node_modules 版本 | 对照 |", "|---|---|---|---|---|");
  for (const item of report.projects) {
    const installed = item.fix_preview?.installed_versions || {};
    const locked = item.fix_preview?.lockfile_versions || {};
    for (const [name, versions] of Object.entries(installed)) {
      const lockVersions = locked[name] || [];
      const matches = versions.length > 0 && versions.every((version) => lockVersions.includes(version));
      lines.push(`| ${item.name} | ${name} | ${lockVersions.join(", ") || "未解析"} | ${versions.join(", ") || "未解析"} | ${matches ? "match" : "mismatch"} |`);
    }
  }
  lines.push(
    "",
    "## 使用方式",
    "",
    "- `npm run audit:security`：生成本报告；高危/严重或超出已接受阈值会失败。",
    "- `npm run audit:raw:console`、`npm run audit:raw:www`、`npm run audit:raw:docs`：查看各站点 npm 原始审计结果。",
    "",
    "## 当前处理原则",
    "",
    "- 不使用 `npm audit fix --force` 强行升大版本，避免把官网或文档站构建链路打断。",
    "- 当前应用之外的研究资料不参与本地应用与审计门禁。",
  );
  return lines.join("\n");
}

mkdirSync(REPORT_DIR, { recursive: true });
const projects = PROJECTS.map(runAudit);
const failed = projects.filter((item) => item.status === "failed");
const report = {
  generated_at: new Date().toISOString(),
  status: failed.length ? "failed" : projects.every((item) => item.status === "passed") ? "passed" : "passed-with-accepted-residuals",
  failed_project_ids: failed.map((item) => item.id),
  projects,
};

writeFileSync(JSON_REPORT, `${JSON.stringify(report, null, 2)}\n`, "utf8");
writeFileSync(MARKDOWN_REPORT, buildMarkdown(report), "utf8");
console.log(JSON.stringify({ status: report.status, report: JSON_REPORT, failed_project_ids: report.failed_project_ids }, null, 2));

if (failed.length) {
  process.exitCode = 1;
}
