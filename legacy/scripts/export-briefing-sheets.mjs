import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const requireFromConsole = createRequire(path.join(repoRoot, 'apps', 'console', 'package.json'));
const { chromium } = requireFromConsole('playwright');

function parseArgs(argv) {
  const args = {
    inputDir: path.join(repoRoot, 'apps', 'api', 'sandbox', 'reports'),
    outputDir: path.join(repoRoot, 'apps', 'api', 'sandbox', 'reports', '攻击面评测单页导出'),
    format: 'both',
    width: 1440,
    height: 1800
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const next = argv[index + 1];
    if (arg === '--input-dir' && next) {
      args.inputDir = path.resolve(next);
      index += 1;
    } else if (arg === '--output-dir' && next) {
      args.outputDir = path.resolve(next);
      index += 1;
    } else if (arg === '--format' && next) {
      args.format = next;
      index += 1;
    } else if (arg === '--width' && next) {
      args.width = Number(next);
      index += 1;
    } else if (arg === '--height' && next) {
      args.height = Number(next);
      index += 1;
    }
  }
  return args;
}

async function exists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function findChromeExecutable() {
  if (process.env.CHROME_EXECUTABLE_PATH && await exists(process.env.CHROME_EXECUTABLE_PATH)) {
    return process.env.CHROME_EXECUTABLE_PATH;
  }
  const candidates = [
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
  ];
  for (const candidate of candidates) {
    if (await exists(candidate)) {
      return candidate;
    }
  }
  return '';
}

async function findBriefingSheets(inputDir) {
  const entries = await fs.readdir(inputDir, { withFileTypes: true });
  return entries
    .filter((entry) => entry.isFile() && entry.name.startsWith('攻击面评测单页-') && entry.name.endsWith('.html'))
    .filter((entry) => !entry.name.includes('索引'))
    .map((entry) => path.join(inputDir, entry.name))
    .sort((a, b) => path.basename(a).localeCompare(path.basename(b), 'zh-Hans-CN'));
}

function outputBaseName(htmlPath) {
  return path.basename(htmlPath, '.html').replace(/^攻击面评测单页-/, '');
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const htmlFiles = await findBriefingSheets(args.inputDir);
  await fs.mkdir(args.outputDir, { recursive: true });

  if (!htmlFiles.length) {
    console.log(JSON.stringify({
      ok: false,
      reason: '未找到攻击面评测单页 HTML，请先生成 briefing_sheets。',
      input_dir: args.inputDir,
      output_dir: args.outputDir,
      files: []
    }, null, 2));
    process.exitCode = 2;
    return;
  }

  const executablePath = await findChromeExecutable();
  if (!executablePath) {
    console.log(JSON.stringify({
      ok: false,
      reason: '未找到 Chrome/Chromium，无法生成 PNG/PDF。可设置 CHROME_EXECUTABLE_PATH 指向浏览器可执行文件。',
      input_dir: args.inputDir,
      output_dir: args.outputDir,
      files: []
    }, null, 2));
    process.exitCode = 3;
    return;
  }

  const browser = await chromium.launch({
    headless: true,
    executablePath,
    args: ['--no-sandbox', '--disable-dev-shm-usage']
  });
  const page = await browser.newPage({ viewport: { width: args.width, height: args.height } });
  const files = [];
  const writePng = args.format === 'png' || args.format === 'both';
  const writePdf = args.format === 'pdf' || args.format === 'both';

  try {
    for (const htmlPath of htmlFiles) {
      const base = outputBaseName(htmlPath);
      const pngPath = path.join(args.outputDir, `${base}.png`);
      const pdfPath = path.join(args.outputDir, `${base}.pdf`);
      await page.goto(pathToFileURL(htmlPath).href, { waitUntil: 'domcontentloaded', timeout: 30000 });
      await page.waitForTimeout(300);

      const record = { html_path: htmlPath, surface_id: base, png_path: '', pdf_path: '' };
      if (writePng) {
        const sheet = await page.$('.sheet');
        if (sheet) {
          await sheet.screenshot({ path: pngPath });
        } else {
          await page.screenshot({ path: pngPath, fullPage: true });
        }
        record.png_path = pngPath;
      }
      if (writePdf) {
        await page.pdf({
          path: pdfPath,
          printBackground: true,
          preferCSSPageSize: true,
          format: 'A4',
          margin: { top: '8mm', right: '8mm', bottom: '8mm', left: '8mm' }
        });
        record.pdf_path = pdfPath;
      }
      files.push(record);
    }
  } finally {
    await browser.close();
  }

  console.log(JSON.stringify({
    ok: true,
    generated_at: new Date().toISOString(),
    chrome_executable: executablePath,
    input_dir: args.inputDir,
    output_dir: args.outputDir,
    format: args.format,
    file_count: files.length,
    files
  }, null, 2));
}

main().catch((error) => {
  console.error(JSON.stringify({
    ok: false,
    reason: error instanceof Error ? error.message : String(error),
    stack: error instanceof Error ? error.stack : ''
  }, null, 2));
  process.exitCode = 1;
});
