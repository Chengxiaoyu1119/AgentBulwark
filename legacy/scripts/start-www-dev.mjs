import { spawn } from 'node:child_process';
import http from 'node:http';
import { createServer } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const host = '127.0.0.1';
const port = 4321;
const url = `http://${host}:${port}/`;
const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, '..');
const wwwRoot = join(repoRoot, 'apps', 'www');
const viteBin = join(wwwRoot, 'node_modules', 'vite', 'bin', 'vite.js');

function requestHome() {
  return new Promise((resolveRequest) => {
    let settled = false;
    const settle = (result) => {
      if (settled) return;
      settled = true;
      resolveRequest(result);
    };
    const statusIsReachable = (statusCode) => Boolean(statusCode && statusCode >= 200 && statusCode < 500);

    const request = http.get(url, { timeout: 1200 }, (response) => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => {
        body += chunk;
        if (body.length > 4096) {
          settle({ ok: statusIsReachable(response.statusCode), body });
          request.destroy();
        }
      });
      response.on('end', () => {
        settle({ ok: statusIsReachable(response.statusCode), body });
      });
      response.on('aborted', () => settle({ ok: statusIsReachable(response.statusCode), body }));
      response.on('error', () => settle({ ok: false, body }));
      response.on('close', () => settle({ ok: statusIsReachable(response.statusCode), body }));
    });

    request.on('timeout', () => {
      settle({ ok: false, body: '' });
      request.destroy();
    });
    request.on('error', () => settle({ ok: false, body: '' }));
    request.on('close', () => settle({ ok: false, body: '' }));
  });
}

function canListen() {
  return new Promise((resolveListen) => {
    const server = createServer();
    server.once('error', () => resolveListen(false));
    server.once('listening', () => {
      server.close(() => resolveListen(true));
    });
    server.listen(port, host);
  });
}

const home = await requestHome();
if (home.ok && home.body.includes('智安哨')) {
  console.log(`官网已经在运行：${url}`);
  console.log('如果需要重启，请先关闭旧的 start:www 终端。');
  process.exit(0);
}

if (!(await canListen())) {
  console.error(`端口 ${port} 已被其他程序占用，官网没有启动。`);
  console.error('请先关闭占用该端口的程序，或者检查 VSCode 是否已经有一个 start:www 任务在运行。');
  process.exit(1);
}

const child = spawn(process.execPath, [viteBin, '--host', host, '--port', String(port), '--strictPort'], {
  cwd: wwwRoot,
  stdio: 'inherit',
  shell: false
});

child.on('close', (code) => process.exit(code ?? 1));
