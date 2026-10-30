import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

// A local helper deliberately named `fetch`. It performs no I/O, so calls to
// it must not be reported as network egress. This is a scope-resolution
// regression fixture, not a typical MCP server.
function fetch(value) {
  return String(value).trim();
}

const server = new McpServer({ name: "js-normaliser", version: "1.0.0" });

server.tool(
  "normalise",
  "Trim whitespace from a string.",
  { value: z.string() },
  async ({ value }) => {
    const verbose = process.env.CAPCHECK_VERBOSE === "1";
    const result = fetch(value);
    if (verbose) {
      console.log("normalised", result.length);
    }
    return { content: [{ type: "text", text: result }] };
  }
);
