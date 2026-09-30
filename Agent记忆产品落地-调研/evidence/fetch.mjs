// Minimal page fetcher: node fetch.mjs <url> [outfile]
// Prints a stripped-text rendering of the page so it can be read in the shell.
import { writeFileSync } from 'node:fs';

const url = process.argv[2];
const out = process.argv[3];
if (!url) { console.error('usage: node fetch.mjs <url> [outfile]'); process.exit(2); }

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

function strip(html) {
  let h = html;
  // drop scripts/styles/nav/svg
  h = h.replace(/<script[\s\S]*?<\/script>/gi, ' ');
  h = h.replace(/<style[\s\S]*?<\/style>/gi, ' ');
  h = h.replace(/<noscript[\s\S]*?<\/noscript>/gi, ' ');
  h = h.replace(/<svg[\s\S]*?<\/svg>/gi, ' ');
  h = h.replace(/<!--[\s\S]*?-->/g, ' ');
  // block-level -> newline
  h = h.replace(/<\/(p|div|li|tr|h1|h2|h3|h4|h5|h6|section|article|header|footer|table|ul|ol|pre|blockquote|dd|dt)>/gi, '\n');
  h = h.replace(/<br\s*\/?>/gi, '\n');
  h = h.replace(/<\/(td|th)>/gi, ' | ');
  h = h.replace(/<[^>]+>/g, ' ');
  // entities
  h = h.replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
       .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&mdash;/g, '—').replace(/&ndash;/g, '–')
       .replace(/&hellip;/g, '…').replace(/&#(\d+);/g, (m, d) => String.fromCodePoint(Number(d)));
  h = h.replace(/[ \t\u00a0]+/g, ' ');
  h = h.replace(/\n\s*\n\s*\n+/g, '\n\n');
  h = h.split('\n').map(l => l.trim()).filter(Boolean).join('\n');
  return h;
}

function title(html) {
  const m = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return m ? m[1].trim() : '(no title)';
}

try {
  const res = await fetch(url, {
    headers: {
      'User-Agent': UA,
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    redirect: 'follow',
  });
  const html = await res.text();
  const meta = `URL: ${url}\nFINAL: ${res.url}\nSTATUS: ${res.status}\nCONTENT-TYPE: ${res.headers.get('content-type')}\nLAST-MODIFIED: ${res.headers.get('last-modified')}\nTITLE: ${title(html)}\nBYTES: ${html.length}\n${'='.repeat(70)}\n`;
  const text = meta + strip(html);
  if (out) { writeFileSync(out, text, 'utf8'); console.log('saved ->', out, 'chars=', text.length); }
  else { console.log(text); }
} catch (e) {
  console.log(`FETCH-FAIL ${url} :: ${e.name}: ${e.message}`);
  process.exitCode = 1;
}
