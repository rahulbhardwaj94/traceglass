// Bundle runtime assets into the CLI package so a published `traceglass`
// (installed via npx) is fully self-contained: the web dashboard (so it needs
// no separate @traceglass/web dependency) and a sample trace (so `traceglass
// demo` works on a stranger's machine with no input file). Runs after `tsc -b`.
import { copyFileSync, cpSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const cliDist = join(here, '..', 'dist');

// 1. the built web SPA -> dist/web
const webSrc = join(here, '..', '..', 'web', 'dist');
const webDest = join(cliDist, 'web');
if (!existsSync(join(webSrc, 'index.html'))) {
  console.error(`✗ web build not found at ${webSrc} — run \`npm run build -w @traceglass/web\` first.`);
  process.exit(1);
}
mkdirSync(webDest, { recursive: true });
cpSync(webSrc, webDest, { recursive: true });
console.log(`bundled web dashboard -> ${webDest}`);

// 2. a sample trace -> dist/demo-trace.json (the collections loop+error run)
const demoSrc = join(here, '..', '..', '..', 'fixtures', 'sample-run-loop.json');
const demoDest = join(cliDist, 'demo-trace.json');
if (!existsSync(demoSrc)) {
  console.error(`✗ demo trace not found at ${demoSrc}`);
  process.exit(1);
}
copyFileSync(demoSrc, demoDest);
console.log(`bundled demo trace    -> ${demoDest}`);
