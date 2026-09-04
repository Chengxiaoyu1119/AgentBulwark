import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from '../apps/console/node_modules/typescript/lib/typescript.js';

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
  'gateway',
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
const allowedFallbackFiles = new Set(['index.ts', 'overview.ts']);
const allowedVisualFiles = new Set([
  'agent.css',
  'experiments.css',
  'foundation.css',
  'operations.css',
  'settings.css',
  'settings-experiments.css',
  'shared.css',
  'surface.css'
]);
const allowedPageExtensions = new Set(['.tsx']);
const scannedExtensions = new Set(['.css', '.ts', '.tsx']);
const experimentOwnerPrefixes = [
  'zh-agent-',
  'zh-attack-',
  'zh-authorized-',
  'zh-brief-',
  'zh-calibration-',
  'zh-causal-',
  'zh-comparison-',
  'zh-competition-',
  'zh-custom-attack-',
  'zh-dashboard-',
  'zh-delivery-',
  'zh-dual-model-',
  'zh-feature-map-',
  'zh-lab-',
  'zh-report-',
  'zh-roadmap-',
  'zh-scenario-',
  'zh-surface-',
  'zh-target-',
  'zh-testset-',
  'zh-threshold-'
];

const colorPattern = /(?<!&)#[0-9a-fA-F]{3,8}|rgba?\(/g;
const cssTokenPattern = /var\(--/g;
const zhiAnTokenDefinitionPattern = /(--zh-[a-z0-9-]+)\s*:/g;
const zhiAnTokenReferencePattern = /var\((--zh-[a-z0-9-]+)/g;
const inlineStylePattern = /style=\{\{|styles=\{\{/g;
const sharedCssLiteralSpacingPattern =
  /(?:^|\n)\s*(?:gap|row-gap|column-gap|margin(?:-(?:top|right|bottom|left))?|padding(?:-(?:top|right|bottom|left))?|font-size|border-radius|z-index|min-height|max-height|width|height|line-height|grid-template-columns|outline(?:-offset)?|border(?:-(?:top|right|bottom|left))?)\s*:\s*[^;\n]*\b\d+px\b/g;
const cssAntiPattern = /gradient|transition\s*:\s*all|z-index\s*:\s*\d+/gi;
const governedAntdPrimitives = new Set([
  'Button',
  'Card',
  'Tag',
  'Badge',
  'Progress',
  'Alert',
  'Table',
  'Tabs',
  'Select',
  'Input'
]);
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

function resolveRuntimeSourceModule(importer, specifier) {
  let unresolved;
  if (specifier.startsWith('@/')) {
    unresolved = path.join(srcRoot, specifier.slice(2));
  } else if (specifier.startsWith('.')) {
    unresolved = path.resolve(path.dirname(importer), specifier);
  } else {
    return null;
  }

  const candidates = [
    unresolved,
    `${unresolved}.ts`,
    `${unresolved}.tsx`,
    path.join(unresolved, 'index.ts'),
    path.join(unresolved, 'index.tsx')
  ];
  return (
    candidates.find(
      (candidate) =>
        ['.ts', '.tsx'].includes(path.extname(candidate)) && fs.existsSync(candidate) && fs.statSync(candidate).isFile()
    ) ?? null
  );
}

function runtimeModuleSpecifiers(file, text) {
  const sourceFile = ts.createSourceFile(
    file,
    text,
    ts.ScriptTarget.Latest,
    true,
    file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS
  );
  const specifiers = [];

  for (const statement of sourceFile.statements) {
    if (ts.isImportDeclaration(statement) && ts.isStringLiteral(statement.moduleSpecifier)) {
      const clause = statement.importClause;
      if (clause?.isTypeOnly) continue;
      if (
        clause &&
        !clause.name &&
        clause.namedBindings &&
        ts.isNamedImports(clause.namedBindings) &&
        clause.namedBindings.elements.length > 0 &&
        clause.namedBindings.elements.every((element) => element.isTypeOnly)
      ) {
        continue;
      }
      specifiers.push(statement.moduleSpecifier.text);
    }
    if (
      ts.isExportDeclaration(statement) &&
      statement.moduleSpecifier &&
      ts.isStringLiteral(statement.moduleSpecifier) &&
      !statement.isTypeOnly
    ) {
      specifiers.push(statement.moduleSpecifier.text);
    }
  }

  function visit(node) {
    if (
      ts.isCallExpression(node) &&
      node.expression.kind === ts.SyntaxKind.ImportKeyword &&
      node.arguments.length === 1 &&
      ts.isStringLiteral(node.arguments[0])
    ) {
      specifiers.push(node.arguments[0].text);
    }
    ts.forEachChild(node, visit);
  }
  visit(sourceFile);
  return specifiers;
}

function analyzeAntdPrimitives(file, text) {
  const sourceFile = ts.createSourceFile(
    file,
    text,
    ts.ScriptTarget.Latest,
    true,
    file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS
  );
  const importedPrimitives = new Map();
  const namespaceImports = new Set();
  let directImportCount = 0;

  for (const statement of sourceFile.statements) {
    if (ts.isImportDeclaration(statement) && ts.isStringLiteral(statement.moduleSpecifier)) {
      const moduleName = statement.moduleSpecifier.text;
      if (moduleName !== 'antd' && !moduleName.startsWith('antd/')) continue;
      const clause = statement.importClause;
      if (!clause || clause.isTypeOnly || !clause.namedBindings) continue;
      if (ts.isNamespaceImport(clause.namedBindings)) {
        namespaceImports.add(clause.namedBindings.name.text);
        continue;
      }
      if (!ts.isNamedImports(clause.namedBindings)) continue;
      for (const element of clause.namedBindings.elements) {
        if (element.isTypeOnly) continue;
        const importedName = element.propertyName?.text ?? element.name.text;
        if (!governedAntdPrimitives.has(importedName)) continue;
        importedPrimitives.set(element.name.text, importedName);
        directImportCount += 1;
      }
    }

    if (
      ts.isExportDeclaration(statement) &&
      statement.moduleSpecifier &&
      ts.isStringLiteral(statement.moduleSpecifier) &&
      (statement.moduleSpecifier.text === 'antd' || statement.moduleSpecifier.text.startsWith('antd/')) &&
      statement.exportClause &&
      ts.isNamedExports(statement.exportClause) &&
      !statement.isTypeOnly
    ) {
      directImportCount += statement.exportClause.elements.filter((element) => {
        const exportedName = element.propertyName?.text ?? element.name.text;
        return governedAntdPrimitives.has(exportedName);
      }).length;
    }
  }

  let directUsageCount = 0;
  function visit(node) {
    if (ts.isJsxOpeningLikeElement(node)) {
      const tagName = node.tagName;
      if (ts.isIdentifier(tagName)) {
        if (importedPrimitives.has(tagName.text) || governedAntdPrimitives.has(tagName.text)) directUsageCount += 1;
      } else if (
        ts.isPropertyAccessExpression(tagName) &&
        ts.isIdentifier(tagName.expression) &&
        namespaceImports.has(tagName.expression.text) &&
        governedAntdPrimitives.has(tagName.name.text)
      ) {
        directUsageCount += 1;
        directImportCount = Math.max(directImportCount, 1);
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(sourceFile);

  return { directImportCount, directUsageCount };
}

function runtimeSourceClosure(entryRelativePath) {
  const entry = path.join(root, entryRelativePath);
  const visited = new Set();
  const pending = [entry];
  while (pending.length) {
    const file = pending.pop();
    if (!file || visited.has(file)) continue;
    visited.add(file);
    const text = fs.readFileSync(file, 'utf8');
    for (const specifier of runtimeModuleSpecifiers(file, text)) {
      const dependency = resolveRuntimeSourceModule(file, specifier);
      if (dependency && !visited.has(dependency)) pending.push(dependency);
    }
  }
  return [...visited].sort();
}

function classTokensForFiles(filesToScan) {
  const exact = new Set();
  const prefixes = new Set();
  for (const file of filesToScan) {
    const text = fs.readFileSync(file, 'utf8');
    for (const match of text.matchAll(/\bzh-[a-z0-9_-]+/g)) {
      const className = match[0];
      if (className.endsWith('--')) prefixes.add(className);
      else exact.add(className);
    }
  }
  return { exact, prefixes };
}

function isClassTokenUsed(className, tokens) {
  return tokens.exact.has(className) || [...tokens.prefixes].some((prefix) => className.startsWith(prefix));
}

function cssRuleSelectors(text) {
  const selectors = [];
  let segmentStart = 0;
  let quote = '';
  let inComment = false;

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    const next = text[index + 1];
    if (inComment) {
      if (char === '*' && next === '/') {
        inComment = false;
        index += 1;
      }
      continue;
    }
    if (!quote && char === '/' && next === '*') {
      inComment = true;
      index += 1;
      continue;
    }
    if (quote) {
      if (char === '\\') index += 1;
      else if (char === quote) quote = '';
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }
    if (char === '{') {
      const prelude = text.slice(segmentStart, index).trim();
      if (prelude && !prelude.startsWith('@') && !prelude.includes(';')) selectors.push(prelude);
      segmentStart = index + 1;
    } else if (char === '}') {
      segmentStart = index + 1;
    }
  }
  return selectors;
}

function selectorOwnerClasses(selector) {
  return selector
    .split(',')
    .map((branch) => branch.match(/\.((?:zh-)[a-z0-9_-]+)/)?.[1] ?? '')
    .filter(Boolean);
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

const visualRoot = path.join(designRoot, '视觉系统');
const unexpectedVisualEntries = listDirectoryEntries(visualRoot)
  .filter((entry) => entry.isDirectory() || !allowedVisualFiles.has(entry.name))
  .map((entry) => `src/design/视觉系统/${entry.name}`);

const fallbackRoot = path.join(srcRoot, 'fallback');
const unexpectedFallbackEntries = listDirectoryEntries(fallbackRoot)
  .filter((entry) => entry.isDirectory() || !allowedFallbackFiles.has(entry.name))
  .map((entry) => `src/fallback/${entry.name}`);
const fallbackRuntimeText = Array.from(allowedFallbackFiles, (file) => readMaybe(`src/fallback/${file}`)).join('\n');
const retiredFallbackMarkers = Array.from(
  new Set(fallbackRuntimeText.match(/fallback(?:Overview|Policies|Scenarios)|offline(?:Policies|Scenarios)/g) ?? [])
).sort();

const productionSourceFiles = runtimeSourceClosure('src/main.tsx');
const productionSourceRelativeFiles = productionSourceFiles.map(toRelativeSourcePath);
const productionForbiddenModules = new Set([
  'src/api.ts',
  'src/app/attackLabApi.ts',
  'src/app/fallbackReport.ts',
  'src/app/reportEvaluationApi.ts',
  'src/app/useAppActions.ts'
]);
const productionExperimentModules = productionSourceRelativeFiles
  .filter((file) => productionForbiddenModules.has(file))
  .sort();
const productionClassTokens = classTokensForFiles(productionSourceFiles);

const files = walkFiles(srcRoot)
  .filter((file) => scannedExtensions.has(path.extname(file)))
  .map(toRelativeSourcePath)
  .sort();
const runtimeEventSubscriptionOwners = files
  .filter(
    (file) =>
      productionSourceRelativeFiles.includes(file) &&
      !file.includes('.test.') &&
      readMaybe(file).includes('subscribeRuntimeEvents')
  )
  .sort();
const expectedRuntimeEventSubscriptionOwners = ['src/app/apiRequest.ts', 'src/app/runtimeEventConnection.ts'];
const unexpectedRuntimeEventSubscriptionOwners = runtimeEventSubscriptionOwners.filter(
  (file) => !expectedRuntimeEventSubscriptionOwners.includes(file)
);
const missingRuntimeEventSubscriptionOwners = expectedRuntimeEventSubscriptionOwners.filter(
  (file) => !runtimeEventSubscriptionOwners.includes(file)
);

const summary = files.map((file) => {
  const text = readMaybe(file);
  const { directImportCount: directAntdPrimitiveImportCount, directUsageCount: directAntdPrimitiveCount } =
    analyzeAntdPrimitives(file, text);
  return {
    file,
    lines: text ? text.split(/\r?\n/).length : 0,
    bytes: Buffer.byteLength(text),
    hardcoded_color_count: countMatches(text, colorPattern),
    token_usage_count: countMatches(text, cssTokenPattern),
    css_antipattern_count: path.extname(file) === '.css' ? countMatches(text, cssAntiPattern) : 0,
    inline_style_count: countMatches(text, inlineStylePattern),
    direct_antd_primitive_count: directAntdPrimitiveCount,
    direct_antd_primitive_import_count: directAntdPrimitiveImportCount,
    direct_antd_primitive_outside_ui_count: isUiComponentFile(file)
      ? 0
      : Math.max(directAntdPrimitiveImportCount, directAntdPrimitiveCount)
  };
});

const appText = readMaybe('src/App.tsx');
const componentMatches = appText.match(/^function [A-Z][A-Za-z0-9_]+/gm) ?? [];
const maxFile = summary.reduce((largest, item) => (item.bytes > largest.bytes ? item : largest), summary[0]);
const directDecisionMarkupCount = countMatches(appText, /className=\{`decision \$\{/g);
const tokenDefinitionFile = 'src/design/tokens.css';
const cssHardcodedColorCount = summary
  .filter((item) => item.file.endsWith('.css') && item.file !== tokenDefinitionFile)
  .reduce((sum, item) => sum + item.hardcoded_color_count, 0);
const sourceHardcodedColorCount = summary
  .filter((item) => item.file !== tokenDefinitionFile)
  .reduce((sum, item) => sum + item.hardcoded_color_count, 0);
const sourceTokenUsageCount = summary.reduce((sum, item) => sum + item.token_usage_count, 0);
const cssAntiPatternCount = summary.reduce((sum, item) => sum + item.css_antipattern_count, 0);
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
const directAntdPrimitiveImportCount = summary.reduce(
  (sum, item) => sum + item.direct_antd_primitive_import_count,
  0
);
const directAntdPrimitiveOutsideUiCount = summary.reduce(
  (sum, item) => sum + item.direct_antd_primitive_outside_ui_count,
  0
);
const antdPrimitiveWrapperCount = directAntdPrimitiveCount - directAntdPrimitiveOutsideUiCount;
const tokenInfo = fileInfo('src/design/tokens.css');
const tokenDefinitionText = readMaybe('src/design/tokens.css');
const styleEntryText = readMaybe('src/styles.css');
const visualEntryText = readMaybe('src/视觉系统.css');
const foundationVisualText = readMaybe('src/design/视觉系统/foundation.css');
const operationsVisualText = readMaybe('src/design/视觉系统/operations.css');
const experimentsVisualText = readMaybe('src/design/视觉系统/experiments.css');
const sharedVisualText = readMaybe('src/design/视觉系统/shared.css');
const settingsVisualText = readMaybe('src/design/视觉系统/settings.css');
const settingsExperimentsVisualText = readMaybe('src/design/视觉系统/settings-experiments.css');
const agentVisualText = readMaybe('src/design/视觉系统/agent.css');
const surfaceVisualText = readMaybe('src/design/视觉系统/surface.css');
const productionVisualText = [foundationVisualText, operationsVisualText, sharedVisualText, settingsVisualText].join(
  '\n'
);
const definedZhiAnTokens = new Set(
  Array.from(tokenDefinitionText.matchAll(zhiAnTokenDefinitionPattern), (match) => match[1])
);
const referencedProductionZhiAnTokens = Array.from(
  new Set(Array.from(productionVisualText.matchAll(zhiAnTokenReferencePattern), (match) => match[1]))
).sort();
const undefinedProductionZhiAnTokens = referencedProductionZhiAnTokens.filter(
  (token) => !definedZhiAnTokens.has(token)
);
const experimentOwnershipText = [
  experimentsVisualText,
  settingsExperimentsVisualText,
  agentVisualText,
  surfaceVisualText
].join('\n');
const sharedCssLiteralSpacingCount = countMatches(sharedVisualText, sharedCssLiteralSpacingPattern);
const productionCssLiteralSpacingCount = countMatches(productionVisualText, sharedCssLiteralSpacingPattern);
const appLayoutSelectorCounts = countCssSelectorDefinitions(productionVisualText, criticalAppLayoutSelectors);
const duplicateAppLayoutSelectors = Object.entries(appLayoutSelectorCounts)
  .filter(([, count]) => count > 1)
  .map(([selector, count]) => ({ selector, count }));
const expectedStyleEntry = [
  "@import './design/视觉系统/foundation.css';",
  "@import './design/视觉系统/operations.css';"
].join('\n');
const expectedVisualEntry = [
  "@import './design/视觉系统/shared.css';",
  "@import './design/视觉系统/settings.css';"
].join('\n');
const styleEntryMatchesOwnership = styleEntryText.trim() === expectedStyleEntry;
const visualEntryMatchesOwnership = visualEntryText.trim() === expectedVisualEntry;
const operationExperimentOwners = Array.from(
  new Set(
    cssRuleSelectors([operationsVisualText, settingsVisualText].join('\n'))
      .flatMap(selectorOwnerClasses)
      .filter((className) => experimentOwnerPrefixes.some((prefix) => className.startsWith(prefix)))
  )
).sort();
const experimentProductionOwners = Array.from(
  new Set(
    cssRuleSelectors(experimentOwnershipText)
      .flatMap(selectorOwnerClasses)
      .filter((className) => isClassTokenUsed(className, productionClassTokens))
  )
).sort();
const historicalStyleImport = '../design/视觉系统/experiments.css';
const missingHistoricalStyleImports = ['src/pages/Dashboard.tsx', 'src/pages/ReportPanel.tsx'].filter(
  (file) => !readMaybe(file).includes(historicalStyleImport)
);
const visualStyleFiles = [
  'src/styles.css',
  'src/视觉系统.css',
  'src/design/视觉系统/foundation.css',
  'src/design/视觉系统/operations.css',
  'src/design/视觉系统/experiments.css',
  'src/design/视觉系统/shared.css',
  'src/design/视觉系统/settings.css',
  'src/design/视觉系统/settings-experiments.css',
  'src/design/视觉系统/agent.css',
  'src/design/视觉系统/surface.css'
];
const visualStyleFileInfo = Object.fromEntries(visualStyleFiles.map((file) => [file, fileInfo(file)]));
const darkLayoutRules = [
  {
    selector: '.zh-app-sider.zh-app-sider--dark',
    declaration: 'background: var(--zh-bg-panel-dark)',
    present: hasCssSelectorDeclaration(
      productionVisualText,
      '.zh-app-sider.zh-app-sider--dark',
      /background:\s*var\(--zh-bg-panel-dark\)/
    )
  },
  {
    selector: '.zh-app-header.zh-app-header--dark',
    declaration: 'background: var(--zh-bg-panel-dark)',
    present: hasCssSelectorDeclaration(
      productionVisualText,
      '.zh-app-header.zh-app-header--dark',
      /background:\s*var\(--zh-bg-panel-dark\)/
    )
  },
  {
    selector: '.zh-app-header.zh-app-header--dark .ant-btn-default',
    declaration: 'background: var(--zh-bg-panel-dark)',
    present: hasCssSelectorDeclaration(
      productionVisualText,
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
const inlineStyleHotspots = summary.filter((item) => item.inline_style_count > 2);

const budgets = {
  app_max_lines: 300,
  source_file_max_lines: 300,
  css_hardcoded_color_max: 0,
  source_hardcoded_color_max: 0,
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
  unexpected_visual_entry_max: 0,
  unexpected_fallback_entry_max: 0,
  retired_fallback_marker_max: 0,
  production_experiment_module_max: 0,
  duplicate_app_layout_selector_max: 0,
  shared_css_literal_spacing_max: 0,
  production_css_literal_spacing_max: 0,
  css_antipattern_max: 0,
  unexpected_runtime_event_subscription_owner_max: 0,
  missing_runtime_event_subscription_owner_max: 0,
  undefined_production_token_max: 0,
  operation_experiment_owner_max: 0,
  experiment_production_owner_max: 0,
  missing_historical_style_import_max: 0,
  visual_file_max_lines: {
    'src/styles.css': 10,
    'src/视觉系统.css': 10,
    'src/design/视觉系统/foundation.css': 250,
    'src/design/视觉系统/operations.css': 1600,
    'src/design/视觉系统/experiments.css': 3400,
    'src/design/视觉系统/shared.css': 350,
    'src/design/视觉系统/settings.css': 550,
    'src/design/视觉系统/settings-experiments.css': 550,
    'src/design/视觉系统/agent.css': 400,
    'src/design/视觉系统/surface.css': 1000
  }
};
const oversizedVisualFiles = Object.entries(budgets.visual_file_max_lines)
  .map(([file, maxLines]) => ({ file, maxLines, lines: visualStyleFileInfo[file]?.lines ?? 0 }))
  .filter((item) => item.lines > item.maxLines);

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
if (unexpectedVisualEntries.length > budgets.unexpected_visual_entry_max) {
  violations.push(`Unexpected visual system entries: ${unexpectedVisualEntries.join(', ')}`);
}
if (unexpectedFallbackEntries.length > budgets.unexpected_fallback_entry_max) {
  violations.push(`Unexpected runtime fallback entries: ${unexpectedFallbackEntries.join(', ')}`);
}
if (retiredFallbackMarkers.length > budgets.retired_fallback_marker_max) {
  violations.push(`Retired demo fallback exports returned to the runtime bundle: ${retiredFallbackMarkers.join(', ')}`);
}
if (productionExperimentModules.length > budgets.production_experiment_module_max) {
  violations.push(
    `Experiment API modules leaked into the production dependency graph: ${productionExperimentModules.join(', ')}`
  );
}
if (!styleEntryMatchesOwnership) {
  violations.push('src/styles.css must import only foundation.css and operations.css in the documented order');
}
if (!visualEntryMatchesOwnership) {
  violations.push('src/视觉系统.css must import only shared.css and settings.css in the documented order');
}
if (oversizedVisualFiles.length) {
  violations.push(
    `Visual CSS line budget exceeded: ${oversizedVisualFiles
      .map((item) => `${item.file} ${item.lines}/${item.maxLines}`)
      .join(', ')}`
  );
}
if (operationExperimentOwners.length > budgets.operation_experiment_owner_max) {
  violations.push(`Experiment-owned selectors leaked into operations.css: ${operationExperimentOwners.join(', ')}`);
}
if (experimentProductionOwners.length > budgets.experiment_production_owner_max) {
  violations.push(`Production-owned selectors leaked into experiments.css: ${experimentProductionOwners.join(', ')}`);
}
if (missingHistoricalStyleImports.length > budgets.missing_historical_style_import_max) {
  violations.push(`Historical pages missing explicit experiment styles: ${missingHistoricalStyleImports.join(', ')}`);
}
if (duplicateAppLayoutSelectors.length > budgets.duplicate_app_layout_selector_max) {
  violations.push(
    `Duplicate app layout selectors: ${duplicateAppLayoutSelectors
      .map((item) => `${item.selector} x${item.count}`)
      .join(', ')}`
  );
}
if (sharedCssLiteralSpacingCount > budgets.shared_css_literal_spacing_max) {
  violations.push(
    `Shared visual CSS contains hardcoded spacing/typography literals: ${sharedCssLiteralSpacingCount}/${budgets.shared_css_literal_spacing_max}`
  );
}
if (productionCssLiteralSpacingCount > budgets.production_css_literal_spacing_max) {
  violations.push(
    `Production visual CSS hardcoded spacing/typography budget exceeded: ${productionCssLiteralSpacingCount}/${budgets.production_css_literal_spacing_max}`
  );
}
if (cssAntiPatternCount > budgets.css_antipattern_max) {
  violations.push(`CSS anti-pattern budget exceeded: ${cssAntiPatternCount}/${budgets.css_antipattern_max}`);
}
if (unexpectedRuntimeEventSubscriptionOwners.length > budgets.unexpected_runtime_event_subscription_owner_max) {
  violations.push(
    `Runtime event subscription duplicated outside its owner: ${unexpectedRuntimeEventSubscriptionOwners.join(', ')}`
  );
}
if (missingRuntimeEventSubscriptionOwners.length > budgets.missing_runtime_event_subscription_owner_max) {
  violations.push(`Runtime event subscription owner missing: ${missingRuntimeEventSubscriptionOwners.join(', ')}`);
}
if (undefinedProductionZhiAnTokens.length > budgets.undefined_production_token_max) {
  violations.push(`Production CSS references undefined design tokens: ${undefinedProductionZhiAnTokens.join(', ')}`);
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
  defined_zhi_an_token_count: definedZhiAnTokens.size,
  referenced_production_zhi_an_tokens: referencedProductionZhiAnTokens,
  undefined_production_zhi_an_tokens: undefinedProductionZhiAnTokens,
  css_antipattern_count: cssAntiPatternCount,
  shared_css_literal_spacing_count: sharedCssLiteralSpacingCount,
  production_css_literal_spacing_count: productionCssLiteralSpacingCount,
  inline_style_count: inlineStyleCount,
  inline_style_locations: inlineStyleLocations,
  top_inline_style_files: inlineStyleLocations.slice(0, 10),
  direct_antd_primitive_count: directAntdPrimitiveCount,
  direct_antd_primitive_import_count: directAntdPrimitiveImportCount,
  direct_antd_primitive_outside_ui_count: directAntdPrimitiveOutsideUiCount,
  antd_primitive_wrapper_count: antdPrimitiveWrapperCount,
  unexpected_src_entries: unexpectedSrcEntries,
  unexpected_component_entries: unexpectedComponentEntries,
  unexpected_page_entries: unexpectedPageEntries,
  unexpected_design_entries: unexpectedDesignEntries,
  unexpected_visual_entries: unexpectedVisualEntries,
  unexpected_fallback_entries: unexpectedFallbackEntries,
  retired_fallback_markers: retiredFallbackMarkers,
  production_source_files: productionSourceRelativeFiles,
  production_experiment_modules: productionExperimentModules,
  runtime_event_subscription_owners: runtimeEventSubscriptionOwners,
  unexpected_runtime_event_subscription_owners: unexpectedRuntimeEventSubscriptionOwners,
  missing_runtime_event_subscription_owners: missingRuntimeEventSubscriptionOwners,
  production_class_count: productionClassTokens.exact.size,
  production_class_prefixes: Array.from(productionClassTokens.prefixes).sort(),
  style_entry_matches_ownership: styleEntryMatchesOwnership,
  visual_entry_matches_ownership: visualEntryMatchesOwnership,
  operation_experiment_owners: operationExperimentOwners,
  experiment_production_owners: experimentProductionOwners,
  missing_historical_style_imports: missingHistoricalStyleImports,
  visual_style_files: visualStyleFileInfo,
  oversized_visual_files: oversizedVisualFiles,
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
    fallback_files: Array.from(allowedFallbackFiles).sort(),
    visual_files: Array.from(allowedVisualFiles).sort(),
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
    'Keep production selectors in operations.css and historical research selectors in experiments.css.',
    'Keep src/styles.css and src/视觉系统.css as import-only ownership manifests.',
    'Reserve inline styles for values that must be calculated from runtime data.',
    'Split App.tsx by page only after shared UI components are stable.',
    'Avoid adding new page-level CSS files unless they map to a clear feature boundary.'
  ]
};

console.log(JSON.stringify(result, null, 2));
if (violations.length) {
  process.exit(1);
}
