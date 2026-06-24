import { spawn } from 'node:child_process';

/** Open a URL in the default browser, cross-platform. Best-effort. */
export function openBrowser(url: string): void {
  const platform = process.platform;
  const cmd = platform === 'darwin' ? 'open' : platform === 'win32' ? 'cmd' : 'xdg-open';
  const args = platform === 'win32' ? ['/c', 'start', '""', url] : [url];
  try {
    const child = spawn(cmd, args, { stdio: 'ignore', detached: true });
    child.on('error', () => {
      /* ignore — user can open the printed URL manually */
    });
    child.unref();
  } catch {
    /* ignore */
  }
}
