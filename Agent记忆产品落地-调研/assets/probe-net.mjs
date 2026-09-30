// 网络可达性探针：逐个 URL 尝试 fetch，打印状态码/长度/错误
const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36';
const targets = [
  'https://arxiv.org/abs/2504.19413',
  'https://arxiv.org/html/2504.19413v1',
  'https://github.com/mem0ai/mem0',
  'https://raw.githubusercontent.com/mem0ai/mem0/main/README.md',
  'https://api.github.com/repos/mem0ai/mem0',
  'https://cdn.jsdelivr.net/gh/mem0ai/mem0@main/README.md',
  'https://gitee.com/mirrors/mem0',
  'https://pypi.org/pypi/mem0/json',
  'https://www.getzep.com/pricing/',
  'https://docs.mem0.ai/open-source/features/overview',
  'https://platform.openai.com/docs/guides/memory',
  'https://openreview.net/forum?id=U51WxL5W0I',
];

for (const url of targets) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 20000);
  try {
    const r = await fetch(url, { redirect: 'follow', signal: ctrl.signal, headers: { 'user-agent': ua, accept: 'text/html,application/json,text/plain,*/*' } });
    const body = await r.text();
    console.log(`OK   ${r.status}  bytes=${body.length}  final=${r.url}`);
  } catch (e) {
    console.log(`FAIL ${(e && (e.cause?.code || e.name || e.message)) || e}  ${url}`);
  } finally {
    clearTimeout(t);
  }
  console.log(`     ^ ${url}`);
}
