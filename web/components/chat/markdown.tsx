'use client';

// Simple markdown renderer — no dependencies needed
// Handles: bold, italic, code, headers, lists, tables, links, horizontal rules

export function Markdown({ content }: { content: string }) {
  const html = renderMarkdown(content);
  return (
    <div
      className="prose-chat text-sm leading-relaxed"
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}

function renderMarkdown(text: string): string {
  // Split into lines for block-level processing
  const lines = text.split('\n');
  const result: string[] = [];
  let inCodeBlock = false;
  let codeContent: string[] = [];

  let inTable = false;
  let tableRows: string[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Code blocks
    if (line.trimStart().startsWith('```')) {
      if (inCodeBlock) {
        result.push(
          `<pre class="bg-bg2 border border-border rounded-[4px] p-3 my-2 overflow-x-auto text-xs font-[family-name:var(--font-mono)] text-green"><code>${escapeHtml(codeContent.join('\n'))}</code></pre>`
        );
        codeContent = [];
        inCodeBlock = false;
      } else {
        flushTable();
        inCodeBlock = true;
      }
      continue;
    }

    if (inCodeBlock) {
      codeContent.push(line);
      continue;
    }

    // Table detection
    if (line.includes('|') && line.trim().startsWith('|')) {
      tableRows.push(line);
      inTable = true;
      continue;
    } else if (inTable) {
      flushTable();
    }

    // Horizontal rule
    if (/^---+$/.test(line.trim())) {
      result.push('<hr class="border-border my-3" />');
      continue;
    }

    // Headers
    if (line.startsWith('#### ')) {
      result.push(`<h4 class="text-text-bright font-semibold text-sm mt-3 mb-1">${inline(line.slice(5))}</h4>`);
      continue;
    }
    if (line.startsWith('### ')) {
      result.push(`<h3 class="text-text-bright font-semibold text-base mt-3 mb-1">${inline(line.slice(4))}</h3>`);
      continue;
    }
    if (line.startsWith('## ')) {
      result.push(`<h2 class="text-amber font-bold text-base mt-4 mb-1 font-[family-name:var(--font-display)] tracking-wider uppercase">${inline(line.slice(3))}</h2>`);
      continue;
    }
    if (line.startsWith('# ')) {
      result.push(`<h1 class="text-amber font-bold text-lg mt-4 mb-2 font-[family-name:var(--font-display)] tracking-wider uppercase">${inline(line.slice(2))}</h1>`);
      continue;
    }

    // Unordered list
    if (/^\s*[-*]\s/.test(line)) {
      const content = line.replace(/^\s*[-*]\s/, '');
      result.push(`<div class="flex gap-2 ml-2"><span class="text-amber shrink-0">-</span><span>${inline(content)}</span></div>`);
      continue;
    }

    // Ordered list
    if (/^\s*\d+\.\s/.test(line)) {
      const match = line.match(/^\s*(\d+)\.\s(.*)/);
      if (match) {
        result.push(`<div class="flex gap-2 ml-2"><span class="text-amber shrink-0 font-[family-name:var(--font-mono)] text-xs">${match[1]}.</span><span>${inline(match[2])}</span></div>`);
        continue;
      }
    }

    // Empty line
    if (line.trim() === '') {
      result.push('<div class="h-2"></div>');
      continue;
    }

    // Normal paragraph
    result.push(`<p>${inline(line)}</p>`);
  }

  // Flush any remaining code block or table
  if (inCodeBlock) {
    result.push(
      `<pre class="bg-bg2 border border-border rounded-[4px] p-3 my-2 overflow-x-auto text-xs font-[family-name:var(--font-mono)] text-green"><code>${escapeHtml(codeContent.join('\n'))}</code></pre>`
    );
  }
  flushTable();

  return result.join('\n');

  function flushTable() {
    if (tableRows.length === 0) return;
    inTable = false;

    const rows = tableRows.map(r =>
      r.split('|').map(c => c.trim()).filter(c => c !== '')
    );
    tableRows = [];

    if (rows.length < 2) {
      // Not a real table, just render as text
      for (const r of rows) {
        result.push(`<p>${inline(r.join(' | '))}</p>`);
      }
      return;
    }

    // Check if row 2 is a separator (---+)
    const isSeparator = rows[1]?.every(c => /^[-:]+$/.test(c));
    const headerRow = rows[0];
    const dataRows = isSeparator ? rows.slice(2) : rows.slice(1);

    let html = '<div class="overflow-x-auto my-2"><table class="w-full text-xs border-collapse">';
    html += '<thead><tr>';
    for (const cell of headerRow) {
      html += `<th class="text-left text-amber font-[family-name:var(--font-mono)] px-2 py-1.5 border-b border-border font-semibold">${inline(cell)}</th>`;
    }
    html += '</tr></thead><tbody>';
    for (const row of dataRows) {
      html += '<tr>';
      for (const cell of row) {
        html += `<td class="px-2 py-1.5 border-b border-border/50 text-text-dim">${inline(cell)}</td>`;
      }
      html += '</tr>';
    }
    html += '</tbody></table></div>';
    result.push(html);
  }
}

// Inline markdown: bold, italic, code, links
function inline(text: string): string {
  let result = escapeHtml(text);

  // Inline code
  result = result.replace(/`([^`]+)`/g, '<code class="bg-bg2 text-green px-1 py-0.5 rounded text-xs font-[family-name:var(--font-mono)]">$1</code>');

  // Bold
  result = result.replace(/\*\*(.+?)\*\*/g, '<strong class="text-text-bright font-semibold">$1</strong>');

  // Italic
  result = result.replace(/\*(.+?)\*/g, '<em>$1</em>');

  // Links — validate protocol to prevent javascript:/data: XSS
  result = result.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_match, text, url) => {
    if (isSafeUrl(url)) {
      return `<a href="${escapeAttr(url)}" target="_blank" rel="noopener noreferrer" class="text-amber hover:text-amber-dim underline">${text}</a>`;
    }
    return text; // Strip unsafe link, keep text
  });

  return result;
}

function isSafeUrl(url: string): boolean {
  // Only allow http/https/mailto protocols
  const trimmed = url.trim().toLowerCase();
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://') || trimmed.startsWith('mailto:')) {
    return true;
  }
  // Relative URLs starting with /
  if (trimmed.startsWith('/') && !trimmed.startsWith('//')) {
    return true;
  }
  return false;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function escapeAttr(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}
