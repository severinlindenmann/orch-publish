// store markdown: the content lives in content/*.md in the repository and is read-only at run time.
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const CONTENT = join(dirname(fileURLToPath(import.meta.url)), "content");

export function openStore() {
  return {
    writable: false,
    list: () => readdirSync(CONTENT).filter((f) => f.endsWith(".md")).sort()
      .map((f) => ({ text: readFileSync(join(CONTENT, f), "utf8").split("\n")[0].replace(/^#+\s*/, "") })),
  };
}
