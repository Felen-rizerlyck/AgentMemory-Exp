const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36';
const targets = [
  'https://api.github.com/rate_limit',
  'https://gitee.com/mirrors/mem0/raw/master/README.md',
  'https://r.jina.ai/https://github.com/mem0ai/mem0',
  'https://pypi.org/pypi/mem0ai/json',
  'https://pypi.org/simple/mem0ai/',
  'https://huggingface.co/api/models?search=memory',
  'https://api.openai.com/v1/models',
  'https://www.nist.gov/itl/ai-risk-management-framework',
  'https://genai.owasp.org/llm-top-10/',
  'https://hai.stanford.edu',
  'https://dl.acm.org/doi/10.1145/3626772.3657878',
  'https://aclanthology.org/2024.acl-long.747/',
];
for (const url of targets) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 15000);
  try {
    const r = await fetch(url, { redirect: 'follow', signal: ctrl.signal, headers: { 'user-agent': ua, accept: '*/*' } });
    const b = await r.text();
    let extra = '';
    if (url.endsWith('/rate_limit')) { try { const j = JSON.parse(b); extra = ` core=${j.resources.core.remaining}/${j.resources.core.limit} reset=${new Date(j.resources.core.reset * 1000).toISOString()}`; } catch {} }
    console.log(`OK   ${r.status} bytes=${b.length}${extra}`);
  } catch (e) { console.log(`FAIL ${(e?.cause?.code) || e?.name || e}`); }
  finally { clearTimeout(t); }
  console.log(`     ^ ${url}`);
}
