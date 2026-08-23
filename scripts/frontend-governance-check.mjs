import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// npm's `--prefix apps/console` changes dependency resolution, not the
// process working directory. Resolve the audited frontend from this script's
// location so `npm run ui:audit` and direct invocation inspect the same files.
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const root = path.join(repositoryRoot, 'apps', 'console');
const srcRoot = path.join(root, 'src');
const allowedSrcDirectories = new Set(['app', 'components', 'design', 'fallback', 'pages', 'test', 'types']);
const allowedSrcFiles = new Set([
  'App.tsx',
  'api.test.ts',
  'api.ts',
  'fallback.ts',
  'main.tsx',
  'styles.css',
  'types.ts',
  'utils.test.ts',
  'utils.ts',
  '\u89c6\u89c9\u7cfb\u7edf.css'
]);
const allowedComponentDirectories = new Set([
  'alerts',
  'audit',
  'agent',
  'dashboard',
  'evidence',
  'lab',
  'policy',
  'report',
  'scenarios',
  'settings',
  'surface',
  'ui'
]);
const allowedComponentRootFiles = new Set(['README.md', 'index.ts']);
const allowedDesignFiles = new Set(['README.md', 'tokens.css']);
const allowedDesignDirectories = new Set(['视觉系统']);
const allowedPageExtensions = new Set(['.tsx']);
const scannedExtensions = new Set(['.css', '.ts', '.tsx']);

const colorPattern = /#[0-9a-fA-F]{3,8}|rgba?\(/g;
const cssTokenPattern = /var\(--/g;
const inlineStylePattern = /style=\{\{|styles=\{\{/g;
const directAntdPrimitivePattern = /<(Button|Card|Tag|Badge|Progress|Alert|Table|Tabs|Select|Input)\b/g;
const criticalAppLayoutSelectors = new Set([
  '.zh-app-loading',
  '.zh-app-loading__panel',
  '.zh-app-logo',
  '.zh-app-layout',
  '.zh-app-sider',
  '.zh-app-brand',
  '.zh-app-menu',
  '.zh-app-header',
  '.zh-main-content'
]);

function countMatches(text, pattern) {
  return (text.match(pattern) ?? []).length;
}

function lineNumbersForMatches(text, pattern) {
  return text.split(/\r?\n/).flatMap((line, index) => {
    pattern.lastIndex = 0;
    return pattern.test(line) ? [index + 1] : [];
  });
}

function countCssSelectorDefinitions(text, selectors) {
  const counts = Object.fromEntries(Array.from(selectors, (selector) => [selector, 0]));
  const withoutComments = text.replace(/\/\*[\s\S]*?\*\//g, '');
  const selectorBlockPattern = /(?:^|})\s*([^{}]+)\{/g;

  for (const match of withoutComments.matchAll(selectorBlockPattern)) {
    for (const selector of match[1].split(',').map((item) => item.trim())) {
      if (selector in counts) {
        counts[selector] += 1;
      }
    }
  }

  return counts;
}

function hasCssSelectorDeclaration(text, selector, declarationPattern) {
  const withoutComments = text.replace(/\/\*[\s\S]*?\*\//g, '');
  const selectorBlockPattern = /([^{}]+)\{([^{}]*)\}/g;

  for (const match of withoutComments.matchAll(selectorBlockPattern)) {
    const selectors = match[1].split(',').map((item) => item.trim());
    if (selectors.includes(selector) && declarationPattern.test(match[2])) {
      return true;
    }
  }

  return false;
}

function readMaybe(relativePath) {
  const fullPath = path.join(root, relativePath);
  if (!fs.existsSync(fullPath)) {
    return '';
  }
  return fs.readFileSync(fullPath, 'utf8');
}

function fileInfo(relativePath) {
  const text = readMaybe(relativePath);
  return {
    lines: text ? text.split(/\r?\n/).length : 0,
    bytes: Buffer.byteLength(text)
  };
}

function walkFiles(dir) {
  if (!fs.existsSync(dir)) {
    return [];
  }
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      return walkFiles(fullPath);
    }
    return [fullPath];
  });
}

function toRelativeSourcePath(fullPath) {
  return path.relative(root, fullPath).replaceAll(path.sep, '/');
}

function listDirectoryEntries(dir) {
  if (!fs.existsSync(dir)) {
    return [];
  }
  return fs.readdirSync(dir, { withFileTypes: true });
}

function isUiComponentFile(file) {
  return file.startsWith('src/components/ui/');
}

const srcEntries = fs.existsSync(srcRoot) ? fs.readdirSync(srcRoot, { withFileTypes: true }) : [];
const unexpectedSrcEntries = srcEntries
  .filter((entry) => {
    if (entry.isDirectory()) {
      return !allowedSrcDirectories.has(entry.name);
    }
    return !allowedSrcFiles.has(entry.name);
  })
  .map((entry) => `src/${entry.name}`);

const componentsRoot = path.join(srcRoot, 'components');
const unexpectedComponentEntries = listDirectoryEntries(componentsRoot)
  .filter((entry) => {
    if (entry.isDirectory()) {
      return !allowedComponentDirectories.has(entry.name);
    }
    return !allowedComponentRootFiles.has(entry.name);
  })
  .map((entry) => `src/components/${entry.name}`);

const pagesRoot = path.join(srcRoot, 'pages');
const unexpectedPageEntries = listDirectoryEntries(pagesRoot)
  .filter((entry) => entry.isDirectory() || !allowedPageExtensions.has(path.extname(entry.name)))
  .map((entry) => `src/pages/${entry.name}`);

const designRoot = path.join(srcRoot, 'design');
const unexpectedDesignEntries = listDirectoryEntries(designRoot)
  .filter((entry) => {
    if (entry.isDirectory()) {
      return !allowedDesignDirectories.has(entry.name);
    }
    return !allowedDesignFiles.has(entry.name);
  })
  .map((entry) => `src/design/${entry.name}`);

const files = walkFiles(srcRoot)
  .filter((file) => scannedExtensions.has(path.extname(file)))
  .map(toRelativeSourcePath)
  .sort();

const summary = files.map((file) => {
  const text = readMaybe(file);
  const directAntdPrimitiveCount = countMatches(text, directAntdPrimitivePattern);
  return {
    file,
    lines: text ? text.split(/\r?\n/).length : 0,
    bytes: Buffer.byteLength(text),
    hardcoded_color_count: countMatches(text, colorPattern),
    token_usage_count: countMatches(text, cssTokenPattern),
    inline_style_count: countMatches(text, inlineStylePattern),
    direct_antd_primitive_count: directAntdPrimitiveCount,
    direct_antd_primitive_outside_ui_count: isUiComponentFile(file) ? 0 : directAntdPrimitiveCount
  };
});

const appText = readMaybe('src/App.tsx');
const componentMatches = appText.match(/^function [A-Z][A-Za-z0-9_]+/gm) ?? [];
const maxFile = summary.reduce((largest, item) => (item.bytes > largest.bytes ? item : largest), summary[0]);
const directDecisionMarkupCount = countMatches(appText, /className=\{`decision \$\{/g);
const cssHardcodedColorCount = summary
  .filter((item) => item.file.endsWith('.css'))
  .reduce((sum, item) => sum + item.hardcoded_color_count, 0);
const sourceHardcodedColorCount = summary.reduce((sum, item) => sum + item.hardcoded_color_count, 0);
const sourceTokenUsageCount = summary.reduce((sum, item) => sum + item.token_usage_count, 0);
const inlineStyleCount = summary.reduce((sum, item) => sum + item.inline_style_count, 0);
const inlineStyleLocations = summary
  .filter((item) => item.inline_style_count > 0)
  .map((item) => ({
    file: item.file,
    count: item.inline_style_count,
    lines: lineNumbersForMatches(readMaybe(item.file), inlineStylePattern)
  }))
  .sort((a, b) => b.count - a.count || a.file.localeCompare(b.file));
const directAntdPrimitiveCount = summary.reduce((sum, item) => sum + item.direct_antd_primitive_count, 0);
const directAntdPrimitiveOutsideUiCount = summary.reduce(
  (sum, item) => sum + item.direct_antd_primitive_outside_ui_count,
  0
);
const antdPrimitiveWrapperCount = directAntdPrimitiveCount - directAntdPrimitiveOutsideUiCount;
const tokenInfo = fileInfo('src/design/tokens.css');
const stylesText = readMaybe('src/styles.css');
const appLayoutSelectorCounts = countCssSelectorDefinitions(stylesText, criticalAppLayoutSelectors);
const duplicateAppLayoutSelectors = Object.entries(appLayoutSelectorCounts)
  .filter(([, count]) => count > 1)
  .map(([selector, count]) => ({ selector, count }));
const darkLayoutRules = [
  {
    selector: '.zh-app-sider.zh-app-sider--dark',
    declaration: 'background: var(--zh-bg-panel-dark)',
    present: hasCssSelectorDeclaration(
      stylesText,
      '.zh-app-sider.zh-app-sider--dark',
      /background:\s*var\(--zh-bg-panel-dark\)/
    )
  },
  {
    selector: '.zh-app-header.zh-app-header--dark',
    declaration: 'background: var(--zh-bg-panel-dark)',
    present: hasCssSelectorDeclaration(
      stylesText,
      '.zh-app-header.zh-app-header--dark',
      /background:\s*var\(--zh-bg-panel-dark\)/
    )
  },
  {
    selector: '.zh-app-header.zh-app-header--dark .ant-btn-default',
    declaration: 'background: var(--zh-bg-panel-dark)',
    present: hasCssSelectorDeclaration(
      stylesText,
      '.zh-app-header.zh-app-header--dark .ant-btn-default',
      /background:\s*var\(--zh-bg-panel-dark\)/
    )
  }
];
const missingDarkLayoutRules = darkLayoutRules.filter((rule) => !rule.present);

const uiComponentDir = path.join(root, 'src', 'components', 'ui');
const uiComponentCount = fs.existsSync(uiComponentDir)
  ? fs.readdirSync(uiComponentDir).filter((name) => name.endsWith('.tsx')).length
  : 0;
const oversizedSourceFiles = summary.filter(
  (item) => (item.file.endsWith('.ts') || item.file.endsWith('.tsx')) && item.lines > 300
);
const inlineStyleHotspots = summary.filter((item) => item.inline_style_count > 24);

const budgets = {
  app_max_lines: 300,
  source_file_max_lines: 300,
  css_hardcoded_color_max: 25,
  source_hardcoded_color_max: 25,
  inline_style_max: 2,
  inline_style_per_file_max: 2,
  ui_component_min: 12,
  token_file_min_bytes: 300,
  direct_antd_primitive_outside_ui_max: 0,
  direct_decision_markup_max: 0,
  unexpected_src_entry_max: 0,
  unexpected_component_entry_max: 0,
  unexpected_page_entry_max: 0,
  unexpected_design_entry_max: 0,
  duplicate_app_layout_selector_max: 0
};

const violations = [];
const appInfo = fileInfo('src/App.tsx');
if (appInfo.lines > budgets.app_max_lines) {
  violations.push(`App.tsx line budget exceeded: ${appInfo.lines}/${budgets.app_max_lines}`);
}
if (oversizedSourceFiles.length) {
  violations.push(
    `TS/TSX file line budget exceeded: ${oversizedSourceFiles
      .map((item) => `${item.file} ${item.lines}/${budgets.source_file_max_lines}`)
      .join(', ')}`
  );
}
if (cssHardcodedColorCount > budgets.css_hardcoded_color_max) {
  violations.push(`CSS hardcoded color budget exceeded: ${cssHardcodedColorCount}/${budgets.css_hardcoded_color_max}`);
}
if (uiComponentCount < budgets.ui_component_min) {
  violations.push(`UI component minimum not met: ${uiComponentCount}/${budgets.ui_component_min}`);
}
if (sourceHardcodedColorCount > budgets.source_hardcoded_color_max) {
  violations.push(
    `Source hardcoded color budget exceeded: ${sourceHardcodedColorCount}/${budgets.source_hardcoded_color_max}`
  );
}
if (inlineStyleCount > budgets.inline_style_max) {
  violations.push(`Inline style budget exceeded: ${inlineStyleCount}/${budgets.inline_style_max}`);
}
if (inlineStyleHotspots.length) {
  violations.push(
    `Inline style per-file budget exceeded: ${inlineStyleHotspots
      .map((item) => `${item.file} ${item.inline_style_count}/${budgets.inline_style_per_file_max}`)
      .join(', ')}`
  );
}
if (tokenInfo.bytes < budgets.token_file_min_bytes) {
  violations.push(`Design token file too small: ${tokenInfo.bytes}/${budgets.token_file_min_bytes} bytes`);
}
if (directAntdPrimitiveOutsideUiCount > budgets.direct_antd_primitive_outside_ui_max) {
  violations.push(
    `Direct Ant Design primitive usage outside ui budget exceeded: ${directAntdPrimitiveOutsideUiCount}/${budgets.direct_antd_primitive_outside_ui_max}`
  );
}
if (directDecisionMarkupCount > budgets.direct_decision_markup_max) {
  violations.push(
    `Direct decision class markup remains: ${directDecisionMarkupCount}/${budgets.direct_decision_markup_max}`
  );
}
if (unexpectedSrcEntries.length > budgets.unexpected_src_entry_max) {
  violations.push(`Unexpected src entries: ${unexpectedSrcEntries.join(', ')}`);
}
if (unexpectedComponentEntries.length > budgets.unexpected_component_entry_max) {
  violations.push(`Unexpected component entries: ${unexpectedComponentEntries.join(', ')}`);
}
if (unexpectedPageEntries.length > budgets.unexpected_page_entry_max) {
  violations.push(`Unexpected page entries: ${unexpectedPageEntries.join(', ')}`);
}
if (unexpectedDesignEntries.length > budgets.unexpected_design_entry_max) {
  violations.push(`Unexpected design entries: ${unexpectedDesignEntries.join(', ')}`);
}
if (duplicateAppLayoutSelectors.length > budgets.duplicate_app_layout_selector_max) {
  violations.push(
    `Duplicate app layout selectors: ${duplicateAppLayoutSelectors
      .map((item) => `${item.selector} x${item.count}`)
      .join(', ')}`
  );
}
if (missingDarkLayoutRules.length) {
  violations.push(
    `Missing dark layout rules: ${missingDarkLayoutRules
      .map((rule) => `${rule.selector} requires ${rule.declaration}`)
      .join(', ')}`
  );
}

const warnings = [];
if (inlineStyleCount > 0) {
  warnings.push(
    `Inline styles remain: ${inlineStyleCount}. Keep them limited to data-driven values and do not increase this count without updating the governance budget.`
  );
}
if (directAntdPrimitiveOutsideUiCount > 0) {
  warnings.push(
    `Direct Ant Design primitive usage outside src/components/ui remains: ${directAntdPrimitiveOutsideUiCount}. Prefer src/components/ui for repeated basic UI patterns.`
  );
}

const result = {
  checked_at: new Date().toISOString(),
  summary,
  app_component_count: componentMatches.length,
  ui_component_count: uiComponentCount,
  direct_decision_markup_count: directDecisionMarkupCount,
  css_hardcoded_color_count: cssHardcodedColorCount,
  source_hardcoded_color_count: sourceHardcodedColorCount,
  source_token_usage_count: sourceTokenUsageCount,
  inline_style_count: inlineStyleCount,
  inline_style_locations: inlineStyleLocations,
  top_inline_style_files: inlineStyleLocations.slice(0, 10),
  direct_antd_primitive_count: directAntdPrimitiveCount,
  direct_antd_primitive_outside_ui_count: directAntdPrimitiveOutsideUiCount,
  antd_primitive_wrapper_count: antdPrimitiveWrapperCount,
  unexpected_src_entries: unexpectedSrcEntries,
  unexpected_component_entries: unexpectedComponentEntries,
  unexpected_page_entries: unexpectedPageEntries,
  unexpected_design_entries: unexpectedDesignEntries,
  app_layout_selector_counts: appLayoutSelectorCounts,
  duplicate_app_layout_selectors: duplicateAppLayoutSelectors,
  dark_layout_rules: darkLayoutRules,
  missing_dark_layout_rules: missingDarkLayoutRules,
  oversized_source_files: oversizedSourceFiles,
  inline_style_hotspots: inlineStyleHotspots,
  largest_file: maxFile,
  budgets,
  structure_rules: {
    src_directories: Array.from(allowedSrcDirectories).sort(),
    component_directories: Array.from(allowedComponentDirectories).sort(),
    page_file_extensions: Array.from(allowedPageExtensions).sort(),
    design_files: Array.from(allowedDesignFiles).sort(),
    design_directories: Array.from(allowedDesignDirectories).sort(),
    antd_wrapper_directory: 'src/components/ui'
  },
  budget_status: violations.length ? 'failed' : 'passed',
  violations,
  warnings,
  recommendations: [
    'Move repeated visual blocks into src/components/ui.',
    'Use Ant Design primitives directly inside src/components/ui only when creating reusable wrappers.',
    'Keep new colors in src/design/tokens.css and consume semantic variables.',
    'Keep src top-level entries within the documented pages/components/design structure.',
    'Keep critical app layout selectors defined once in src/styles.css.',
    'Reserve inline styles for values that must be calculated from runtime data.',
    'Split App.tsx by page only after shared UI components are stable.',
    'Avoid adding new page-level CSS files unless they map to a clear feature boundary.'
  ]
};

console.log(JSON.stringify(result, null, 2));
if (violations.length) {
  process.exit(1);
}
