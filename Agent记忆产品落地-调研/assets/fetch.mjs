// 取数工具（本机 shell 无 curl/git，但 node fetch 可用）
// 用法:
//   node fetch.mjs <target> [outfile] [--html2text]
// target 形式:
//   https://arxiv.org/abs/2504.19413              普通抓取
//   ghapi:owner/repo                                → https://api.github.com/repos/owner/repo
//   ghapi:owner/repo/releases?per_page=5            → 同上，带后缀查询
//   ghfile:owner/repo/README.md[@ref]               → 取文件原文（raw，不走 base64）
//   ghtree:owner/repo[@ref]                         → 递归文件树（找工作目录）
// 例:
//   node fetch.mjs ghapi:mem0ai/mem0
//   node fetch.mjs ghfile:mem0ai/mem0/mem0/memory/main.py@main out.py
import { writeFileSync } from 'node:fs';

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36';

const argv = process.argv.slice(2);
const html2text = argv.includes('--html2text');
const rest = argv.filter(a => a !== '--html2text');
const target = rest[0];
const outfile = rest[1];
if (!target) { console.error('usage: node fetch.mjs <target> [outfile] [--html2text]'); process.exit(2); }

let url, accept = 'text/html,application/json,text/plain,*/*';
if (target.startsWith('ghapi:')) {
  url = 'https://api.github.com/' + target.slice(6).replace(/^repos\//, 'repos/');
  if (!/^https:\/\/api\.github\.com\/repos\//.test(url)) url = 'https://api.github.com/repos/' + target.slice(6);
  accept = 'application/vnd.github+json';
} else if (target.startsWith('ghtree:')) {
  const [repo, ref] = target.slice(7).split('@');
  url = `https://api.github.com/repos/${repo}/git/trees/${ref || 'HEAD'}?recursive=1`;
  accept = 'application/vnd.github+json';
} else if (target.startsWith('ghfile:')) {
  const [repoPath, ref] = target.slice(7).split('@');
  const seg = repoPath.split('/');
  const owner = seg[0], repo = seg[1], path = seg.slice(2).join('/');
  url = `https://api.github.com/repos/${owner}/${repo}/contents/${path}${ref ? `?ref=${ref}` : ''}`;
  accept = 'application/vnd.github.raw';
} else {
  url = target;
}

function strip(h) {
  return h
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<\/(p|div|li|tr|h[1-6]|section|article|br)>/gi, '\n')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&#x27;/g, "'")
    .replace(/[ \t]{2,}/g, ' ')
    .replace(/\n{3,}/g, '\n\n');
}

const ctrl = new AbortController();
const timer = setTimeout(() => ctrl.abort(), 45000);
try {
  const r = await fetch(url, { redirect: 'follow', signal: ctrl.signal, headers: { 'user-agent': UA, accept } });
  let body = await r.text();
  console.log(`[${r.status}] ${url} bytes=${body.length}`);
  if (r.status >= 400) console.log(body.slice(0, 500));
  if (html2text && /<html|<!doctype/i.test(body.slice(0, 400))) body = strip(body);
  if (outfile) { writeFileSync(outfile, body, 'utf8'); console.log(`-> wrote ${outfile}`); }
  else if (r.status < 400) console.log(body);
} catch (e) {
  console.error(`FAIL ${(e?.cause?.code) || e?.name || e} ${url}`);
  process.exit(1);
} finally { clearTimeout(timer); }
