const qs = [
  'all:"LongMemEval"',
  'all:"memory poisoning" AND all:agent',
  'ti:"BEAM" AND abs:memory AND abs:benchmark',
  'all:"agent memory" AND ti:survey'
];
for (const q of qs) {
  const url = `http://export.arxiv.org/api/query?search_query=${encodeURIComponent(q)}&start=0&max_results=6&sortBy=relevance`;
  try {
    const r = await fetch(url, { headers: { 'user-agent': 'research-agent/1.0' } });
    const x = await r.text();
    const entries = [...x.matchAll(/<entry>([\s\S]*?)<\/entry>/g)].map(m => m[1]);
    console.log(`\n### ${q}  (${entries.length} hits)`);
    for (const e of entries) {
      const id = (e.match(/<id>([^<]+)<\/id>/) || [])[1];
      const ti = (e.match(/<title>([\s\S]*?)<\/title>/) || [])[1]?.replace(/\s+/g, ' ').trim();
      const pub = (e.match(/<published>([^<]+)<\/published>/) || [])[1];
      const upd = (e.match(/<updated>([^<]+)<\/updated>/) || [])[1];
      console.log(`- ${id}  pub=${pub?.slice(0,10)} upd=${upd?.slice(0,10)}\n  ${ti}`);
    }
  } catch (e) { console.log(`FAIL ${q}: ${e?.cause?.code || e}`); }
}
