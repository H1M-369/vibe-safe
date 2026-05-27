import * as fs from 'fs';
import PDFDocument from 'pdfkit';
import { ScanResult, Finding, Severity } from './types';

const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: '#DC2626',
  HIGH:     '#D97706',
  MEDIUM:   '#0891B2',
  LOW:      '#6B7280',
};

const MODULE_LABELS: Record<string, string> = {
  legal:         'Legal & Privacy',
  security:      'Security Basics',
  secrets:       'Secrets & Keys',
  abuse:         'Abuse Prevention',
  environment:   'Environment & Config',
  'error-pages': 'Error Pages',
  auth:          'Authentication & Authorization',
};

const SEV_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

function hexToRgb(hex: string): [number, number, number] {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return [r, g, b];
}

function severityBadge(doc: PDFKit.PDFDocument, sev: Severity, x: number, y: number): number {
  const color = SEVERITY_COLORS[sev];
  const [r, g, b] = hexToRgb(color);
  const badgeW = 72;
  const badgeH = 14;
  doc.save()
    .roundedRect(x, y, badgeW, badgeH, 3)
    .fillColor([r, g, b])
    .fill()
    .fillColor('#ffffff')
    .fontSize(7.5)
    .font('Helvetica-Bold')
    .text(sev, x, y + 3, { width: badgeW, align: 'center' })
    .restore();
  return badgeW + 8;
}

function drawHRule(doc: PDFKit.PDFDocument, y: number): void {
  doc.save()
    .moveTo(50, y).lineTo(doc.page.width - 50, y)
    .strokeColor('#E5E7EB').lineWidth(0.5).stroke()
    .restore();
}

function countBySev(findings: Finding[], sev: Severity): number {
  return findings.filter(f => f.severity === sev).length;
}

export async function writePdfReport(result: ScanResult, outputPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 50, size: 'A4', bufferPages: true });
    const stream = fs.createWriteStream(outputPath);
    doc.pipe(stream);
    stream.on('finish', resolve);
    stream.on('error', reject);

    const pageW = doc.page.width;
    const contentW = pageW - 100;

    // ── Cover / Header ────────────────────────────────────────────────────────
    doc.rect(0, 0, pageW, 120).fillColor('#0F0F1A').fill();
    doc.fillColor('#F5EDD8').fontSize(26).font('Helvetica-Bold')
      .text('vibe-safe', 50, 32, { continued: true })
      .fillColor('#9CA3AF').font('Helvetica').fontSize(13)
      .text('  Security Audit Report', { continued: false });

    doc.fillColor('#6B7280').fontSize(9).font('Helvetica')
      .text(`Project: ${result.rootPath}`, 50, 68)
      .text(`Scanned: ${new Date(result.timestamp).toLocaleString()}`, 50, 81)
      .text(`Type: ${result.projectType}${result.frameworks.length ? '  ·  ' + result.frameworks.join(', ') : ''}  ·  Duration: ${result.scanDuration}ms`, 50, 94);

    doc.moveDown(4);

    // ── Summary cards ─────────────────────────────────────────────────────────
    const cards: Array<{ label: string; count: number; color: string }> = [
      { label: 'CRITICAL', count: result.criticalCount, color: '#DC2626' },
      { label: 'HIGH',     count: result.highCount,     color: '#D97706' },
      { label: 'MEDIUM',   count: result.mediumCount,   color: '#0891B2' },
      { label: 'LOW',      count: result.lowCount,      color: '#6B7280' },
    ];
    const cardW = (contentW - 30) / 4;
    let cx = 50;
    const cy = 135;
    for (const card of cards) {
      const [r, g, b] = hexToRgb(card.color);
      doc.save()
        .roundedRect(cx, cy, cardW, 52, 5)
        .fillColor([r, g, b], 0.12)
        .fill()
        .roundedRect(cx, cy, cardW, 52, 5)
        .strokeColor([r, g, b]).lineWidth(1).stroke()
        .fillColor([r, g, b])
        .fontSize(22).font('Helvetica-Bold')
        .text(String(card.count), cx, cy + 7, { width: cardW, align: 'center' })
        .fontSize(7).font('Helvetica-Bold')
        .text(card.label, cx, cy + 34, { width: cardW, align: 'center' })
        .restore();
      cx += cardW + 10;
    }

    doc.y = cy + 68;

    // ── Summary table ─────────────────────────────────────────────────────────
    doc.fillColor('#111827').fontSize(12).font('Helvetica-Bold').text('Audit Summary', 50);
    doc.moveDown(0.4);
    drawHRule(doc, doc.y);
    doc.moveDown(0.4);

    const colW = [180, 65, 65, 65, 65];
    const headers = ['Module', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    let tx = 50;
    doc.font('Helvetica-Bold').fontSize(8).fillColor('#374151');
    headers.forEach((h, i) => {
      doc.text(h, tx, doc.y, { width: colW[i], align: i === 0 ? 'left' : 'center', lineBreak: false });
      tx += colW[i];
    });
    doc.moveDown(0.6);
    drawHRule(doc, doc.y);
    doc.moveDown(0.3);

    for (const ar of result.auditResults) {
      const all = ar.findings;
      const label = MODULE_LABELS[ar.module] ?? ar.module;
      tx = 50;
      const rowY = doc.y;
      doc.font('Helvetica').fontSize(8).fillColor('#111827')
        .text(label, tx, rowY, { width: colW[0], lineBreak: false });
      tx += colW[0];
      const sevs: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
      sevs.forEach((s, i) => {
        const n = countBySev(all, s);
        const clr = n > 0 ? SEVERITY_COLORS[s] : '#9CA3AF';
        const [r, g, b] = hexToRgb(clr);
        doc.fillColor([r, g, b]).font(n > 0 ? 'Helvetica-Bold' : 'Helvetica')
          .text(String(n), tx, rowY, { width: colW[i + 1], align: 'center', lineBreak: false });
        tx += colW[i + 1];
      });
      doc.moveDown(0.6);
    }

    drawHRule(doc, doc.y);
    doc.moveDown(0.3);
    // Total row
    tx = 50;
    const totalY = doc.y;
    doc.font('Helvetica-Bold').fontSize(8).fillColor('#111827')
      .text('TOTAL', tx, totalY, { width: colW[0], lineBreak: false });
    tx += colW[0];
    [result.criticalCount, result.highCount, result.mediumCount, result.lowCount].forEach((n, i) => {
      const sevKey = (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as Severity[])[i];
      const clr = n > 0 ? SEVERITY_COLORS[sevKey] : '#9CA3AF';
      const [r, g, b] = hexToRgb(clr);
      doc.fillColor([r, g, b]).text(String(n), tx, totalY, { width: colW[i + 1], align: 'center', lineBreak: false });
      tx += colW[i + 1];
    });
    doc.moveDown(1.5);

    // ── Findings ─────────────────────────────────────────────────────────────
    doc.fillColor('#111827').fontSize(12).font('Helvetica-Bold').text('Static Analysis Findings');
    doc.moveDown(0.5);

    for (const ar of result.auditResults) {
      if (ar.findings.length === 0) continue;

      const label = MODULE_LABELS[ar.module] ?? ar.module;
      // Module heading
      if (doc.y > doc.page.height - 120) doc.addPage();
      doc.save()
        .rect(50, doc.y, contentW, 18)
        .fillColor('#F3F4F6').fill()
        .fillColor('#111827').fontSize(9).font('Helvetica-Bold')
        .text(label, 56, doc.y + 4, { width: contentW - 12 })
        .restore();
      doc.moveDown(1.2);

      const sorted = [...ar.findings].sort(
        (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
      );

      for (const f of sorted) {
        if (doc.y > doc.page.height - 140) doc.addPage();

        const findingY = doc.y;
        severityBadge(doc, f.severity, 50, findingY);

        doc.fillColor('#111827').fontSize(8.5).font('Helvetica-Bold')
          .text(`${f.id}  —  ${f.title}`, 134, findingY, { width: contentW - 84 });
        doc.moveDown(0.3);

        if (f.file) {
          doc.fillColor('#6B7280').fontSize(7.5).font('Helvetica')
            .text(`File: ${f.file}${f.line ? ':' + f.line : ''}`, 50, doc.y);
          doc.moveDown(0.2);
        }

        if (f.snippet) {
          const snippetY = doc.y;
          doc.save()
            .rect(50, snippetY, contentW, 14)
            .fillColor('#1F2937').fill()
            .fillColor('#FCD34D').fontSize(7).font('Courier')
            .text(f.snippet.slice(0, 100), 56, snippetY + 3, { width: contentW - 12 })
            .restore();
          doc.moveDown(0.9);
        }

        doc.fillColor('#374151').fontSize(7.5).font('Helvetica')
          .text(f.remediation.split('\n')[0], 50, doc.y, { width: contentW });
        doc.moveDown(0.3);

        if (f.autoFixable) {
          doc.fillColor('#059669').fontSize(7).font('Helvetica-Oblique')
            .text('⚡  Auto-fixable with --fix', 50, doc.y);
          doc.moveDown(0.3);
        }

        drawHRule(doc, doc.y);
        doc.moveDown(0.5);
      }
    }

    // ── Active Probe Results ──────────────────────────────────────────────────
    if (result.probeResults.length > 0) {
      const confirmed = result.probeResults.filter(p => p.confirmed);
      if (confirmed.length > 0) {
        if (doc.y > doc.page.height - 150) doc.addPage();
        doc.moveDown(0.5);
        doc.fillColor('#111827').fontSize(12).font('Helvetica-Bold')
          .text('Active Probe Results (Confirmed)');
        doc.moveDown(0.5);

        for (const p of confirmed) {
          if (doc.y > doc.page.height - 140) doc.addPage();

          const pY = doc.y;
          severityBadge(doc, p.severity, 50, pY);
          doc.fillColor('#111827').fontSize(8.5).font('Helvetica-Bold')
            .text(`${p.id}  —  ${p.title}`, 134, pY, { width: contentW - 84 });
          doc.moveDown(0.3);

          doc.fillColor('#6B7280').fontSize(7.5).font('Helvetica')
            .text(`Endpoint: ${p.endpoint}`, 50)
            .text(`Payload:  ${p.payload}`, 50);
          doc.moveDown(0.2);

          const respY = doc.y;
          doc.save()
            .rect(50, respY, contentW, 16)
            .fillColor('#1F2937').fill()
            .fillColor('#9CA3AF').fontSize(7).font('Courier')
            .text(p.response.slice(0, 110), 56, respY + 4, { width: contentW - 12 })
            .restore();
          doc.moveDown(1.1);

          doc.fillColor('#374151').fontSize(7.5).font('Helvetica')
            .text(p.remediation.split('\n')[0], 50, doc.y, { width: contentW });
          doc.moveDown(0.3);
          drawHRule(doc, doc.y);
          doc.moveDown(0.5);
        }
      }
    }

    // ── Footer on every page (bufferPages: true lets us iterate) ────────────
    const totalPages = doc.bufferedPageRange().count;
    for (let i = 0; i < totalPages; i++) {
      doc.switchToPage(i);
      doc.save()
        .fontSize(7).font('Helvetica').fillColor('#9CA3AF')
        .text(
          `vibe-safe  •  Generated ${new Date(result.timestamp).toLocaleString()}  •  Page ${i + 1} of ${totalPages}`,
          50, doc.page.height - 30, { width: contentW, align: 'center' }
        )
        .restore();
    }

    doc.flushPages();
    doc.end();
  });
}
