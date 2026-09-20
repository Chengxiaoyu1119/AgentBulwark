import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";

const root = resolve();
const packageScripts = Object.keys(JSON.parse(readFileSync(resolve(root, "package.json"), "utf8")).scripts || {});
const files = [resolve(root, "README.md"), resolve(root, "CONTRIBUTING.md"), ...markdownFiles(resolve(root, "docs"))]
  .filter((file) => existsSync(file));
const failures = [];

for (const file of files) {
  const text = readFileSync(file, "utf8");
  checkMermaidFences(file, text);
  checkLinks(file, text);
  checkNpmCommands(file, text);
}

if (failures.length) {
  console.error(`GitHub 文档检查失败（${failures.length} 项）：`);
  for (const failure of failures) console.error(`- ${failure}`);
  process.exitCode = 1;
} else {
  console.log(`GitHub 文档检查通过：${files.length} 个 Markdown 文件。`);
}

function markdownFiles(directory) {
  if (!existsSync(directory)) return [];
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) return markdownFiles(path);
    return entry.isFile() && entry.name.endsWith(".md") ? [path] : [];
  });
}

function checkMermaidFences(file, text) {
  let fence = null;
  let contentLines = 0;
  for (const [index, line] of text.split(/\r?\n/).entries()) {
    const match = line.match(/^```([^\s]*)\s*$/);
    if (!match) {
      if (fence) contentLines += 1;
      continue;
    }
    if (!fence) {
      fence = { language: match[1], line: index + 1 };
      contentLines = 0;
      continue;
    }
    if (fence.language === "mermaid" && contentLines === 0) {
      failures.push(`${display(file)}:${fence.line} Mermaid 图不能为空`);
    }
    fence = null;
  }
  if (fence) failures.push(`${display(file)}:${fence.line} 代码围栏未闭合`);
}

function checkLinks(file, text) {
  const markdownLink = /!?\[[^\]]*\]\(([^)\s]+)(?:\s+[^)]*)?\)/g;
  const htmlLink = /<(?:a|img)\b[^>]*?\b(?:href|src)=["']([^"']+)["'][^>]*>/gi;
  for (const match of text.matchAll(markdownLink)) checkLocalTarget(file, match[1]);
  for (const match of text.matchAll(htmlLink)) checkLocalTarget(file, match[1]);
}

function checkLocalTarget(file, rawTarget) {
  const target = rawTarget.replace(/^<|>$/g, "").split("#", 1)[0];
  if (!target || /^(?:https?:|mailto:|tel:|data:)/i.test(target)) return;
  const resolved = resolve(dirname(file), decodeURIComponent(target));
  if (!existsSync(resolved)) {
    failures.push(`${display(file)} 本地链接不存在：${rawTarget}`);
  }
}

function checkNpmCommands(file, text) {
  for (const match of text.matchAll(/\bnpm run ([\w:-]+)/g)) {
    if (!packageScripts.includes(match[1])) {
      failures.push(`${display(file)} 引用了不存在的 npm 脚本：${match[1]}`);
    }
  }
}

function display(file) {
  return relative(root, file).replaceAll("\\", "/");
}
