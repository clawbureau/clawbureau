import type { BadgeColor, BadgeData } from './types';

const COLORS: Record<BadgeColor, string> = { green: '#4c1', blue: '#08c', red: '#e05d44', grey: '#9f9f9f' };

export function resolveBadge(status: string | null, proofTier: string | null): BadgeData {
  if (!status) return { color: 'grey', label: 'Claw Verified', message: 'Unknown' };
  if (status !== 'PASS') return { color: 'red', label: 'Claw Rejected', message: 'Policy Violation' };
  switch (proofTier) {
    case 'gateway': case 'sandbox': case 'tee': case 'witnessed_web':
      return { color: 'green', label: 'Claw Verified', message: proofTier.charAt(0).toUpperCase() + proofTier.slice(1) };
    case 'self': return { color: 'blue', label: 'Claw Verified', message: 'Self' };
    default: return { color: 'blue', label: 'Claw Verified', message: proofTier ?? 'Verified' };
  }
}

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

export function renderBadgeSvg(badge: BadgeData): string {
  const l = esc(badge.label), m = esc(badge.message);
  const lw = Math.round(l.length * 6.5 + 20), mw = Math.round(m.length * 6.5 + 20), tw = lw + mw;
  const c = COLORS[badge.color];
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${tw}" height="20" role="img" aria-label="${l}: ${m}">
  <title>${l}: ${m}</title>
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="r"><rect width="${tw}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)"><rect width="${lw}" height="20" fill="#555"/><rect x="${lw}" width="${mw}" height="20" fill="${c}"/><rect width="${tw}" height="20" fill="url(#s)"/></g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text aria-hidden="true" x="${lw / 2}" y="15" fill="#010101" fill-opacity=".3">${l}</text>
    <text x="${lw / 2}" y="14">${l}</text>
    <text aria-hidden="true" x="${lw + mw / 2}" y="15" fill="#010101" fill-opacity=".3">${m}</text>
    <text x="${lw + mw / 2}" y="14">${m}</text>
  </g></svg>`;
}
