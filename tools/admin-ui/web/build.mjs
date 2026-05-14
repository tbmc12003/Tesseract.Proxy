import * as esbuild from 'esbuild';
import { cp, mkdir } from 'node:fs/promises';

const watch = process.argv.includes('--watch');
const outdir = 'dist';

await mkdir(outdir, { recursive: true });
await cp('public/index.html', `${outdir}/index.html`);

const opts = {
  entryPoints: ['src/main.jsx'],
  bundle: true,
  minify: !watch,
  sourcemap: watch,
  outfile: `${outdir}/bundle.js`,
  format: 'esm',
  target: ['es2020'],
  jsx: 'automatic',
  jsxImportSource: 'preact',
  loader: { '.css': 'text' },
  define: { 'process.env.NODE_ENV': watch ? '"development"' : '"production"' },
};

if (watch) {
  const ctx = await esbuild.context(opts);
  await ctx.watch();
  console.log('esbuild: watching…');
} else {
  await esbuild.build(opts);
  console.log('esbuild: built dist/bundle.js');
}
