import { reportToCsv, toReport } from './aggregation.js';

export function buildExport(groups, records = [], options = {}) {
  const format = options.format === 'csv' ? 'csv' : 'json';
  const includeRaw = Boolean(options.includeRaw);
  const report = toReport(groups, { includeRaw, records });

  if (format === 'csv') {
    return {
      mimeType: 'text/csv;charset=utf-8',
      extension: 'csv',
      content: reportToCsv(groups)
    };
  }

  return {
    mimeType: 'application/json;charset=utf-8',
    extension: 'json',
    content: JSON.stringify(report, null, 2)
  };
}

export function downloadReport(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function timestampForFilename(date = new Date()) {
  return date.toISOString().replace(/[:.]/g, '-').replace('T', '_').replace('Z', 'Z');
}
