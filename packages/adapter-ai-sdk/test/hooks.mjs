// Test-only module resolution. When a package is not installed:
// - capability-resolver-client resolves to the sibling package (../resolver-js);
// - the framework package resolves to the real one if it is installed, else to a stub in test/stubs that follows the
//   framework's documented API (see the stub's header). Install the real package to run the same tests against it.
import { registerHooks } from 'node:module';

const here = (p) => new URL(p, import.meta.url).href;
const STUBS = { ai: here('./stubs/ai.mjs'), '@langchain/core/tools': here('./stubs/langchain-core-tools.mjs') };
export const usedStubs = new Set();

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === 'capability-resolver-client') return { url: here('../../resolver-js/src/index.js'), shortCircuit: true };
    if (specifier in STUBS) {
      try { return nextResolve(specifier, context); } catch { usedStubs.add(specifier); return { url: STUBS[specifier], shortCircuit: true }; }
    }
    return nextResolve(specifier, context);
  },
});
