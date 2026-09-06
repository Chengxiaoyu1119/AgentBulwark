import fs from 'node:fs';
import path from 'node:path';

const cwd = process.cwd();
const root = fs.existsSync(path.join(cwd, 'src')) ? cwd : path.join(cwd, 'apps', 'www');
const srcRoot = path.join(root, 'src');

const allowedSrcDirectories = new Set(['components', 'content', 'hooks', 'pages', 'styles']);
const allowedSrcFiles = new Set(['App.tsx', 'content.ts', 'main.tsx', 'vite-env.d.ts']);
const allowedComponentDirectories = new Set(['landing', 'site']);
const allowedStyleFiles = new Set(['global.css', 'tokens.css']);
const scannedExtensions = new Set(['.css', '.ts', '.tsx']);

const colorPattern = /#[0-9a-fA-F]{3,8}|rgba?\(/g;
const cssTokenPattern = /var\(--/g;
const inlineStylePattern = /style=\{\{|styles=\{\{/g;

function readMaybe(relativePath) {
  const fullPath = path.join(root, relativePath);
  if (!fs.existsSync(fullPath)) return '';
  return fs.readFileSync(fullPath, 'utf8');
}

function walkEntries(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) return walkEntries(fullPath);
    return [fullPath];
  });
}

function listDirectoryEntries(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { withFileTypes: true });
}

function countMatches(text, pattern) {
  return (text.match(pattern) ?? []).length;
}

function toSourcePath(fullPath) {
  return path.relative(root, fullPath).replaceAll(path.sep, '/');
}

function fileInfo(relativePath) {
  const text = readMaybe(relativePath);
  return {
    lines: text ? text.split(/\r?\n/).length : 0,
    bytes: Buffer.byteLength(text)
  };
}

const srcEntries = listDirectoryEntries(srcRoot);
const unexpectedSrcEntries = srcEntries
  .filter((entry) => {
    if (entry.isDirectory()) return !allowedSrcDirectories.has(entry.name);
    return !allowedSrcFiles.has(entry.name);
  })
  .map((entry) => `src/${entry.name}`);

const componentEntries = listDirectoryEntries(path.join(srcRoot, 'components'));
const unexpectedComponentEntries = componentEntries
  .filter((entry) => {
    if (entry.isDirectory()) return !allowedComponentDirectories.has(entry.name);
    return true;
  })
  .map((entry) => `src/components/${entry.name}`);

const styleEntries = listDirectoryEntries(path.join(srcRoot, 'styles'));
const unexpectedStyleEntries = styleEntries
  .filter((entry) => entry.isDirectory() || !allowedStyleFiles.has(entry.name))
  .map((entry) => `src/styles/${entry.name}`);

const emptyDirectories = [];
function collectEmptyDirectories(dir) {
  if (!fs.existsSync(dir)) return;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (!entry.isDirectory()) continue;
    collectEmptyDirectories(fullPath);
    const visibleEntries = fs.readdirSync(fullPath).filter((name) => !name.startsWith('.'));
    if (visibleEntries.length === 0) emptyDirectories.push(toSourcePath(fullPath));
  }
}
collectEmptyDirectories(srcRoot);

const files = walkEntries(srcRoot)
  .filter((file) => scannedExtensions.has(path.extname(file)))
  .map(toSourcePath)
  .sort();

const summary = files.map((file) => {
  const text = readMaybe(file);
  const isTokenFile = file === 'src/styles/tokens.css';
  return {
    file,
    lines: text ? text.split(/\r?\n/).length : 0,
    bytes: Buffer.byteLength(text),
    hardcoded_color_count: isTokenFile ? 0 : countMatches(text, colorPattern),
    token_file_color_count: isTokenFile ? countMatches(text, colorPattern) : 0,
    token_usage_count: countMatches(text, cssTokenPattern),
    inline_style_count: countMatches(text, inlineStylePattern)
  };
});

const appInfo = fileInfo('src/App.tsx');
const componentCount = files.filter((file) => file.startsWith('src/components/') && file.endsWith('.tsx')).length;
const hookCount = files.filter((file) => file.startsWith('src/hooks/') && file.endsWith('.ts')).length;
const hardcodedColorCount = summary.reduce((sum, item) => sum + item.hardcoded_color_count, 0);
const tokenUsageCount = summary.reduce((sum, item) => sum + item.token_usage_count, 0);
const inlineStyleCount = summary.reduce((sum, item) => sum + item.inline_style_count, 0);
const tokenInfo = fileInfo('src/styles/tokens.css');
const oversizedTsFiles = summary.filter((item) => (item.file.endsWith('.ts') || item.file.endsWith('.tsx')) && item.lines > 220);

const budgets = {
  app_max_lines: 80,
  ts_file_max_lines: 220,
  hardcoded_color_max_outside_tokens: 0,
  inline_style_max: 0,
  component_min: 6,
  hook_min: 3,
  token_file_min_bytes: 500,
  unexpected_src_entry_max: 0,
  unexpected_component_entry_max: 0,
  unexpected_style_entry_max: 0,
  empty_directory_max: 0
};

const violations = [];
if (appInfo.lines > budgets.app_max_lines) violations.push(`App.tsx line budget exceeded: ${appInfo.lines}/${budgets.app_max_lines}`);
if (oversizedTsFiles.length) {
  violations.push(
    `TS/TSX file line budget exceeded: ${oversizedTsFiles.map((item) => `${item.file} ${item.lines}/${budgets.ts_file_max_lines}`).join(', ')}`
  );
}
if (hardcodedColorCount > budgets.hardcoded_color_max_outside_tokens) {
  violations.push(`Hardcoded colors outside tokens exceeded: ${hardcodedColorCount}/${budgets.hardcoded_color_max_outside_tokens}`);
}
if (inlineStyleCount > budgets.inline_style_max) {
  violations.push(`Inline style budget exceeded: ${inlineStyleCount}/${budgets.inline_style_max}`);
}
if (componentCount < budgets.component_min) {
  violations.push(`Landing component minimum not met: ${componentCount}/${budgets.component_min}`);
}
if (hookCount < budgets.hook_min) {
  violations.push(`Landing hook minimum not met: ${hookCount}/${budgets.hook_min}`);
}
if (tokenInfo.bytes < budgets.token_file_min_bytes) {
  violations.push(`Design token file too small: ${tokenInfo.bytes}/${budgets.token_file_min_bytes} bytes`);
}
if (unexpectedSrcEntries.length > budgets.unexpected_src_entry_max) {
  violations.push(`Unexpected src entries: ${unexpectedSrcEntries.join(', ')}`);
}
if (unexpectedComponentEntries.length > budgets.unexpected_component_entry_max) {
  violations.push(`Unexpected component entries: ${unexpectedComponentEntries.join(', ')}`);
}
if (unexpectedStyleEntries.length > budgets.unexpected_style_entry_max) {
  violations.push(`Unexpected style entries: ${unexpectedStyleEntries.join(', ')}`);
}
if (emptyDirectories.length > budgets.empty_directory_max) {
  violations.push(`Empty directories: ${emptyDirectories.join(', ')}`);
}

const result = {
  checked_at: new Date().toISOString(),
  summary,
  app_lines: appInfo.lines,
  component_count: componentCount,
  hook_count: hookCount,
  hardcoded_color_count_outside_tokens: hardcodedColorCount,
  token_usage_count: tokenUsageCount,
  inline_style_count: inlineStyleCount,
  unexpected_src_entries: unexpectedSrcEntries,
  unexpected_component_entries: unexpectedComponentEntries,
  unexpected_style_entries: unexpectedStyleEntries,
  empty_directories: emptyDirectories,
  oversized_ts_files: oversizedTsFiles,
  budgets,
  structure_rules: {
    src_directories: Array.from(allowedSrcDirectories).sort(),
    component_directories: Array.from(allowedComponentDirectories).sort(),
    style_files: Array.from(allowedStyleFiles).sort()
  },
  budget_status: violations.length ? 'failed' : 'passed',
  violations,
  recommendations: [
    'Keep page entry in src/pages/LandingPage.tsx and keep App.tsx as orchestration only.',
    'Put repeated landing visuals under src/components/landing and header-level UI under src/components/site.',
    'Add new colors only in src/styles/tokens.css, then consume them with CSS variables.',
    'Do not add empty placeholder folders.'
  ]
};

console.log(JSON.stringify(result, null, 2));
if (violations.length) process.exit(1);
