// store json: one JSON file in DATA_DIR, written to a temporary file first and then renamed, so a crash never
// leaves half a file.
import { readFileSync, writeFileSync, renameSync, mkdirSync } from "node:fs";

export function openStore(dir) {
  mkdirSync(dir, { recursive: true });
  const file = `${dir}/items.json`;
  const read = () => {
    try { return JSON.parse(readFileSync(file, "utf8")); } catch { return []; }
  };
  return {
    writable: true,
    list: () => read().slice(-100).reverse(),
    add: (text) => {
      const items = read();
      items.push({ text, at: new Date().toISOString() });
      writeFileSync(`${file}.tmp`, JSON.stringify(items));
      renameSync(`${file}.tmp`, file);
    },
  };
}
