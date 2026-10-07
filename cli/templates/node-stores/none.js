// store none: kept in memory only, gone after a restart or deploy.
export function openStore() {
  const items = [];
  return {
    writable: true,
    list: () => items.slice(-100).reverse(),
    add: (text) => { items.push({ text, at: new Date().toISOString() }); },
  };
}
