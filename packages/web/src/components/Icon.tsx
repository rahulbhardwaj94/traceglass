// Inline single-stroke glyph set (no icon-font dependency — keeps the bundle
// self-contained and offline). Ported from the traceglass design prototype.

export type IconName =
  | 'rewind'
  | 'back'
  | 'fwd'
  | 'end'
  | 'play'
  | 'pause'
  | 'check'
  | 'link'
  | 'export'
  | 'shield'
  | 'loop'
  | 'cost'
  | 'alert';

export function Icon({ name, size = 16 }: { name: IconName; size?: number }) {
  const s = { width: size, height: size, display: 'block' } as const;
  const sw = {
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.6,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
  };
  switch (name) {
    case 'rewind':
      return (
        <svg style={s} viewBox="0 0 24 24">
          <g {...sw}>
            <path d="M11 6 5 12l6 6M19 6l-6 6 6 6" />
          </g>
        </svg>
      );
    case 'back':
      return (
        <svg style={s} viewBox="0 0 24 24">
          <g {...sw}>
            <path d="M15 6 9 12l6 6M6 5v14" />
          </g>
        </svg>
      );
    case 'fwd':
      return (
        <svg style={s} viewBox="0 0 24 24">
          <g {...sw}>
            <path d="M9 6l6 6-6 6M18 5v14" />
          </g>
        </svg>
      );
    case 'end':
      return (
        <svg style={s} viewBox="0 0 24 24">
          <g {...sw}>
            <path d="M13 6l6 6-6 6M5 6l6 6-6 6" />
          </g>
        </svg>
      );
    case 'play':
      return (
        <svg style={s} viewBox="0 0 24 24">
          <path d="M7 5l12 7-12 7z" fill="currentColor" />
        </svg>
      );
    case 'pause':
      return (
        <svg style={s} viewBox="0 0 24 24">
          <g fill="currentColor">
            <rect x="7" y="5" width="3.4" height="14" rx="1" />
            <rect x="13.6" y="5" width="3.4" height="14" rx="1" />
          </g>
        </svg>
      );
    case 'check':
      return (
        <svg style={s} viewBox="0 0 24 24">
          <g {...sw}>
            <path d="M5 12.5l4.2 4.2L19 7" />
          </g>
        </svg>
      );
    case 'link':
      return (
        <svg style={s} viewBox="0 0 24 24">
          <g {...sw}>
            <path d="M9.5 14.5l5-5M8 12l-2 2a3.5 3.5 0 0 0 5 5l2-2M16 12l2-2a3.5 3.5 0 0 0-5-5l-2 2" />
          </g>
        </svg>
      );
    case 'export':
      return (
        <svg style={s} viewBox="0 0 24 24">
          <g {...sw}>
            <path d="M12 15V4M8 8l4-4 4 4M5 15v3a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-3" />
          </g>
        </svg>
      );
    case 'shield':
      return (
        <svg style={s} viewBox="0 0 24 24">
          <g {...sw}>
            <path d="M12 3l7 3v5c0 4.5-3 7.8-7 9-4-1.2-7-4.5-7-9V6z" />
            <path d="M9 12l2 2 4-4" />
          </g>
        </svg>
      );
    case 'loop':
      return (
        <svg style={s} viewBox="0 0 24 24">
          <g {...sw}>
            <path d="M4 9a6 6 0 0 1 10-3l3 3M20 15a6 6 0 0 1-10 3l-3-3" />
            <path d="M17 3v6h-6M7 21v-6h6" />
          </g>
        </svg>
      );
    case 'cost':
      return (
        <svg style={s} viewBox="0 0 24 24">
          <g {...sw}>
            <path d="M12 3v18M16 7H10a2.5 2.5 0 0 0 0 5h4a2.5 2.5 0 0 1 0 5H8" />
          </g>
        </svg>
      );
    case 'alert':
      return (
        <svg style={s} viewBox="0 0 24 24">
          <g {...sw}>
            <path d="M12 4 2.5 20h19z" />
            <path d="M12 10v4M12 17.5v.01" />
          </g>
        </svg>
      );
    default:
      return null;
  }
}
