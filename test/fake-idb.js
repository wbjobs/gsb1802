// Minimal in-memory IndexedDB implementation: just enough surface for CspStore.

function asyncCb(fn) {
  const req = {};
  queueMicrotask(() => {
    try {
      const value = fn(req);
      req.result = value;
      if (req.onsuccess) req.onsuccess({ target: req });
    } catch (err) {
      req.error = err;
      if (req.onerror) req.onerror({ target: req });
    }
  });
  return req;
}

class FakeObjectStore {
  constructor(records, { keyPath, autoIncrement }, indexes = new Map()) {
    this.records = records;
    this.keyPath = keyPath;
    this.autoIncrement = autoIncrement;
    this.indexes = indexes;
    this._nextKey = 1;
    for (const key of records.keys()) {
      const n = Number(key);
      if (Number.isInteger(n) && n >= this._nextKey) this._nextKey = n + 1;
    }
  }

  _indexValue(value, indexKey) {
    return value[indexKey];
  }

  add(value) {
    return asyncCb(() => {
      let key = value[this.keyPath];
      if (key == null) {
        key = this._nextKey++;
        value = { ...value, [this.keyPath]: key };
      }
      if (this.records.has(key)) throw new Error('constraint error: duplicate key');
      this.records.set(key, value);
      return key;
    });
  }

  put(value) {
    return asyncCb(() => {
      let key = value[this.keyPath];
      if (key == null) {
        key = this._nextKey++;
        value = { ...value, [this.keyPath]: key };
      }
      this.records.set(key, value);
      return key;
    });
  }

  get(key) {
    return asyncCb(() => this.records.get(key));
  }

  getAll() {
    return asyncCb(() => [...this.records.values()]);
  }

  count() {
    return asyncCb(() => this.records.size);
  }

  clear() {
    return asyncCb(() => {
      this.records.clear();
    });
  }

  index(name) {
    return new FakeIndex(this, this.indexes.get(name));
  }

  openCursor() {
    return this.index('__primary__').openCursor();
  }
}

class FakeIndex {
  constructor(store, indexKey) {
    this.store = store;
    this.indexKey = indexKey;
  }

  _orderedKeys() {
    const entries = [...this.store.records.entries()];
    if (this.indexKey === '__primary__') {
      entries.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
      return entries.map(([key, value]) => ({ key, value, sortVal: key }));
    }
    return entries
      .map(([key, value]) => ({ key, value, sortVal: value[this.indexKey] }))
      .sort((a, b) => (a.sortVal < b.sortVal ? -1 : a.sortVal > b.sortVal ? 1 : a.key < b.key ? -1 : 1));
  }

  openCursor() {
    const req = {};
    const rows = this._orderedKeys();
    let pos = 0;
    const makeCursor = () => {
      if (pos >= rows.length) {
        req.result = null;
        if (req.onsuccess) req.onsuccess({ target: req });
        return;
      }
      const row = rows[pos];
      req.result = {
        primaryKey: row.key,
        value: row.value,
        delete: () => {
          this.store.records.delete(row.key);
        },
        continue: () => {
          pos++;
          queueMicrotask(makeCursor);
        },
      };
      if (req.onsuccess) req.onsuccess({ target: req });
    };
    queueMicrotask(makeCursor);
    return req;
  }
}

class FakeTransaction {
  constructor(db, storeNames, mode) {
    this.db = db;
    this.mode = mode;
    this._stores = storeNames;
    this.done = false;
    this._listeners = new Map();
  }

  objectStore(name) {
    return this.db._getStore(name);
  }

  addEventListener(type, fn) {
    if (!this._listeners.has(type)) this._listeners.set(type, new Set());
    this._listeners.get(type).add(fn);
  }

  removeEventListener(type, fn) {
    this._listeners.get(type)?.delete(fn);
  }

  _settle() {
    if (this.done) return;
    this.done = true;
    queueMicrotask(() => {
      if (this._aborted) {
        this._fire('abort');
      } else {
        this._fire('complete');
      }
    });
  }

  _fire(type) {
    for (const fn of this._listeners.get(type) || []) fn({ target: this });
    const handler = this[`on${type}`];
    if (handler) handler({ target: this });
  }
}

export class FakeIDBFactory {
  constructor() {
    this.dbs = new Map();
  }

  open(name) {
    const req = {};
    queueMicrotask(() => {
      let db = this.dbs.get(name);
      if (!db) {
        db = new FakeIDBDatabase();
        this.dbs.set(name, db);
        req.result = db;
        if (req.onupgradeneeded) req.onupgradeneeded({ target: req });
      }
      req.result = db;
      if (req.onsuccess) req.onsuccess({ target: req });
    });
    return req;
  }
}

class FakeIDBDatabase {
  constructor() {
    this.stores = new Map();
  }

  get objectStoreNames() {
    return { contains: (n) => this.stores.has(n) };
  }

  createObjectStore(name, opts = {}) {
    const store = new FakeObjectStore(new Map(), {
      keyPath: opts.keyPath,
      autoIncrement: !!opts.autoIncrement,
    });
    const indexes = new Map();
    store.indexes = indexes;
    this.stores.set(name, { store, indexes, opts });
    return {
      createIndex: (indexName, keyPath) => indexes.set(indexName, keyPath),
    };
  }

  _getStore(name) {
    const entry = this.stores.get(name);
    return entry.store;
  }

  transaction(storeNames, mode) {
    const names = Array.isArray(storeNames) ? storeNames : [storeNames];
    const tx = new FakeTransaction(this, names, mode);
    // Transactions complete after the current task drains; approximate by
    // settling on the next microtask checkpoint following request activity.
    queueMicrotask(() => queueMicrotask(() => tx._settle()));
    return tx;
  }
}

export function makeEvent(overrides = {}) {
  return {
    documentURI: 'https://app.example.com/page',
    referrer: '',
    blockedURI: '',
    violatedDirective: '',
    effectiveDirective: '',
    originalPolicy: "default-src 'none'",
    sourceFile: 'https://app.example.com/app.js',
    sample: '',
    disposition: 'enforce',
    statusCode: 200,
    lineNumber: 0,
    columnNumber: 0,
    ...overrides,
  };
}
