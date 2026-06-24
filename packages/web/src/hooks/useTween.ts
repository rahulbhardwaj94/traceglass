import { useEffect, useRef, useState } from 'react';

const prefersReducedMotion = (): boolean =>
  typeof window !== 'undefined' &&
  typeof window.matchMedia === 'function' &&
  window.matchMedia('(prefers-reduced-motion: reduce)').matches;

/**
 * Eased numeric tween toward `target`. Running totals climb when you scrub.
 * Snaps instantly (no animation) when the user prefers reduced motion.
 */
export function useTween(target: number, dur = 320): number {
  const [val, setVal] = useState(target);
  const ref = useRef({ from: target, to: target, start: 0, raf: 0 });

  useEffect(() => {
    if (prefersReducedMotion()) {
      setVal(target);
      return;
    }
    const o = ref.current;
    o.from = val;
    o.to = target;
    o.start = performance.now();
    cancelAnimationFrame(o.raf);
    const tick = (t: number) => {
      const k = Math.min(1, (t - o.start) / dur);
      const e = 1 - Math.pow(1 - k, 3);
      setVal(o.from + (o.to - o.from) * e);
      if (k < 1) o.raf = requestAnimationFrame(tick);
    };
    o.raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(o.raf);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target, dur]);

  return val;
}
