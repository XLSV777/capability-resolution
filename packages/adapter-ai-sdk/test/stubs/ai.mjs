// Stub of the two 'ai' exports this adapter uses, as documented for AI SDK 7 (checked 2026-10-28):
// - https://ai-sdk.dev/docs/reference/ai-sdk-core/tool : tool(definition) returns the same object; it exists for
//   type inference. Fields used here: description, inputSchema, execute(input, options).
// - https://ai-sdk.dev/docs/reference/ai-sdk-core/json-schema : jsonSchema(schema, options?) wraps a JSON Schema 7.
export const tool = (definition) => definition;
export const jsonSchema = (schema) => ({ jsonSchema: schema, validate: undefined });
