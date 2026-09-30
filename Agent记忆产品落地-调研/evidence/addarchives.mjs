import { readFileSync, writeFileSync } from 'node:fs';

const p = 'F:/AI_Learning/AgentMemory/Agent记忆产品落地-调研/evidence/industry.md';
let t = readFileSync(p, 'utf8');

const map = {
  'I-01': 'evidence/pages/aws-agentcore-pricing.txt',
  'I-02': 'evidence/pages/aws-agentcore-memory.md.txt、evidence/pages/misc-aws.txt',
  'I-03': 'evidence/pages/mem0-how-it-works.md.txt、evidence/pages/mem0-platform-overview.md.txt',
  'I-04': 'evidence/pages/mem0-memory-evaluation.md.txt',
  'I-05': 'evidence/pages/mem0-graph-memory.md.txt',
  'I-06': 'evidence/pages/mem0-pricing.txt',
  'I-07': 'evidence/pages/mem0-platform-faqs.md.txt',
  'I-08': 'evidence/pages/anthropic-claude-memory-support.txt',
  'I-09': 'evidence/pages/anthropic-claude-code-memory.txt',
  'I-10': '无原始存档（见文末存档与溯源说明）',
  'I-11': 'evidence/pages/zep-pricing.txt',
  'I-12': 'evidence/pages/zep-research-benchmarks.txt',
  'I-13': 'evidence/pages/zep-konig-graph-db-blog.txt',
  'I-14': 'evidence/pages/zep-defending-memory-poisoning-blog.txt',
  'I-15': 'evidence/pages/letta-memfs.txt',
  'I-16': 'evidence/pages/letta-pricing.txt',
  'I-17': 'evidence/pages/pinecone-pricing.txt',
  'I-18': 'evidence/pages/owasp-llm08-2025.txt、evidence/pages/owasp-llm08-404.txt（错误 URL 的 404 存档）',
  'I-19': 'evidence/pages/owasp-agentic-top10-2025-12-09.txt',
  'I-20': 'evidence/pages/owasp-memory-attack-memorytrap-2026-05-13.txt',
  'I-21': 'evidence/pages/langchain-memory-concepts.txt',
};

// Split into entry blocks so we only touch the right 访问情况 line.
const parts = t.split(/(?=^### \[I-\d\d\])/m);
let touched = 0;
for (let i = 0; i < parts.length; i++) {
  const m = parts[i].match(/^### \[(I-\d\d)\]/);
  if (!m) continue;
  const key = m[1];
  const archive = map[key];
  if (!archive) { console.error('NO MAP for', key); continue; }
  const lines = parts[i].split('\n');
  for (let j = 0; j < lines.length; j++) {
    if (lines[j].startsWith('- 访问情况:')) {
      if (lines[j].includes('存档：')) break;
      lines[j] = lines[j].replace(/\s*$/, '') + `　|　存档：${archive}`;
      touched++;
      break;
    }
  }
  parts[i] = lines.join('\n');
}
t = parts.join('');
writeFileSync(p, t, 'utf8');
console.log('entries updated:', touched);
