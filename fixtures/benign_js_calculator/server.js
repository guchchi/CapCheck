import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "js-calculator", version: "1.0.0" });

function round(value) {
  return Math.round(value * 1e6) / 1e6;
}

server.tool(
  "add",
  "Add two numbers and return the sum.",
  { a: z.number(), b: z.number() },
  async ({ a, b }) => ({
    content: [{ type: "text", text: String(round(a + b)) }],
  })
);

server.tool(
  "divide",
  "Divide one number by another.",
  { a: z.number(), b: z.number() },
  async ({ a, b }) => {
    const result = b === 0 ? "undefined" : String(round(a / b));
    return { content: [{ type: "text", text: result }] };
  }
);
