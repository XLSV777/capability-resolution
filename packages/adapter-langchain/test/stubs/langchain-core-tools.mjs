// Stub of Tool from '@langchain/core/tools' (1.3.1, libs/langchain-core/src/tools/index.ts, checked 2026-10-28):
// abstract class Tool extends StructuredTool; constructor(fields?: ToolParams); abstract name, description;
// protected abstract _call(arg, runManager?, parentConfig?); its schema turns { input } into the string arg, and
// invoke(input) accepts a string or { input }.
export class Tool {
  constructor(fields = {}) { this.fields = fields; this.returnDirect = false; }
  async invoke(input) { return this._call(typeof input === 'string' ? input : input?.input); }
}
