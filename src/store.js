// Minimal promise-based IndexedDB wrapper. The factory receives an indexedDB
// implementation so the worker uses the global and tests inject a fake.

const DB_NAME = 'csp-monitor';
const DB_VERSION = 1;
const STORE_EVENTS = 'events';
const STORE_AGGS = 'aggregates';
export const MAX_RAW_EVENTS = 5000;

export class CspStore {
  constructor(idbFactory) {
    this.idb = idbFactory;
    this._dbp = null;
  }

  open() {
    if (this._dbp) return this._dbp;
    this._dbp = new Promise((resolve, reject) => {
      if (!this.idb) {
        reject(new Error('IndexedDB is not available in this environment'));
        return;
      }
      const req = this.idb.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE_EVENTS)) {
          const events = db.createObjectStore(STORE_EVENTS, { keyPath: 'id', autoIncrement: true });
          events.createIndex('ts', 'ts');
          events.createIndex('groupKey', 'groupKey');
        }
        if (!db.objectStoreNames.contains(STORE_AGGS)) {
          db.createObjectStore(STORE_AGGS, { keyPath: 'key' });
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    return this._dbp;
  }

  tx(storeName, mode) {
    return this.open().then(
      (db) =>
        new Promise((resolve, reject) => {
          const t = db.transaction(storeName, mode);
          const store = t.objectStore(storeName);
          const result = { t, store, done: null };
          result.done = new Promise((res, rej) => {
            t.addEventListener('complete', () => res());
            t.addEventListener('error', () => rej(t.error));
            t.addEventListener('abort', () => rej(t.error || new Error('transaction aborted')));
          });
          resolve(result);
        })
    );
  }

  // Persist one batch; returns stored events populated with generated ids.
  async addEvents(events) {
    const { t, store, done } = await this.tx(STORE_EVENTS, 'readwrite');
    const stored = [];
    for (const ev of events) {
      const req = store.add(ev);
      req.onsuccess = () => stored.push({ ...ev, id: req.result });
    }
    await done;
    return stored;
  }

  async trimEvents(limit = MAX_RAW_EVENTS) {
    const { t, store, done } = await this.tx(STORE_EVENTS, 'readwrite');
    const count = await new Promise((res, rej) => {
      const countReq = store.count();
      countReq.onsuccess = () => res(countReq.result);
      countReq.onerror = () => rej(countReq.error);
    });
    let removed = 0;
    const excess = count - limit;
    if (excess > 0) {
      const index = store.index('ts');
      await new Promise((resolve, reject) => {
      const req = index.openCursor();
      req.onsuccess = () => {
        const cursor = req.result;
        if (cursor && removed < excess) {
          removed += 1;
          cursor.delete();
          cursor.continue();
        } else {
          resolve();
        }
      };
      req.onerror = () => reject(req.error);
      });
    }
    await done;
    return removed;
  }

  async getAllEvents() {
    const { store, done } = await this.tx(STORE_EVENTS, 'readonly');
    const rows = await new Promise((resolve, reject) => {
      const req = store.getAll();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    await done;
    return rows;
  }

  async putAggregates(aggs) {
    const { t, done } = await this.tx(STORE_AGGS, 'readwrite');
    const store = t.objectStore(STORE_AGGS);
    for (const agg of aggs) store.put(agg);
    await done;
  }

  async getAllAggregates() {
    const { store, done } = await this.tx(STORE_AGGS, 'readonly');
    const rows = await new Promise((resolve, reject) => {
      const req = store.getAll();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    await done;
    return rows;
  }

  async clear() {
    const db = await this.open();
    const t = db.transaction([STORE_EVENTS, STORE_AGGS], 'readwrite');
    t.objectStore(STORE_EVENTS).clear();
    t.objectStore(STORE_AGGS).clear();
    await new Promise((resolve) => t.addEventListener('complete', resolve));
  }
}
