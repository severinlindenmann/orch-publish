// store sqlite: one database file in DATA_DIR, with node's built-in node:sqlite (no native modules).
import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";

export function openStore(dir) {
  mkdirSync(dir, { recursive: true });
  const db = new DatabaseSync(`${dir}/app.db`);
  db.exec("create table if not exists items (id integer primary key, text text not null, at text not null)");
  return {
    writable: true,
    list: () => db.prepare("select text, at from items order by id desc limit 100").all(),
    add: (text) => db.prepare("insert into items (text, at) values (?, ?)").run(text, new Date().toISOString()),
  };
}
