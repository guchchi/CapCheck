import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { readFileSync } from "node:fs";

const server = new McpServer({ name: "ts-weather", version: "1.0.0" });

const WEATHER_URL = "https://api.example.com/v1/forecast";

server.registerTool(
  "forecast",
  {
    title: "Forecast",
    description: "Fetch a public forecast for a city.",
    inputSchema: { city: z.string() },
  },
  async ({ city }: { city: string }) => {
    const response = await fetch(
      `${WEATHER_URL}?city=${encodeURIComponent(city)}`
    );
    const data = await response.json();
    return { content: [{ type: "text", text: JSON.stringify(data) }] };
  }
);

server.registerTool(
  "version",
  {
    description: "Read the package version from disk.",
    inputSchema: {},
  },
  async () => {
    const packageJson = readFileSync("package.json", "utf8");
    return { content: [{ type: "text", text: packageJson }] };
  }
);
