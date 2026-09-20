import { createRecord, createGroup, addRecordToGroup } from './aggregation.js';
import { buildExport } from './export-report.js';

const DB_NAME = 'csp-observatory';
const DB_VERSION = 1;
const RAW_STORE = 'violations';
const GROUP_STORE = 'groups';

let database;
let currentNonce = '';
const groups = new Map();
const stats = {
  total: 0,
  batches: 0,
  droppedBeforeDispatch: 0
};

const dbReady = openDatabase()
  .then((db) => {
    database = db;
    return loadState();
  })
  .catch((error) => {
    database = null;
    console.error('CSP worker database unavailable; using in-memory mode', error);
  });

self.onmessage = async (message) => {
  try {
    await dbReady;
    await handleMessage(message.data);
  } catch (error) {
    post({ type: 'ERROR', error: error.message });
  }
};

async function handleMessage(data) {
  if (!data || typeof data !== 'object') {
    return;
  }

  switch (data.type) {
    case 'INIT':
      currentNonce = data.nonce || '';
      post({ type: 'STATE', groups: publicGroups(), stats: getStats() });
      break;
    case 'REPORT_BATCH':
      await reportBatch(data.events || [], Boolean(data.loadTest));
      break;
    case 'MARK_DROPPED':
      stats.droppedBeforeDispatch += Number(data.count) || 0;
      post({ type: 'STATE', groups: publicGroups(), stats: getStats() });
      break;
    case 'GET_STATE':
      post({ type: 'STATE', groups: publicGroups(), stats: getStats() });
      break;
    case 'CLEAR':
      await clear(data.scope === 'load-test');
      post({ type: 'STATE', groups: publicGroups(), stats: getStats() });
      break;
    case 'EXPORT':
      await sendExport(data.options || {});
      break;
    default:
      break;
  }
}

function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(RAW_STORE)) {
        const store = db.createObjectStore(RAW_STORE, { keyPath: 'id' });
        store.createIndex('fingerprint', 'fingerprint');
        store.createIndex('occurredAt', 'occurredAt');
        store.createIndex('directive', 'directive');
        store.createIndex('origin', 'origin');
        store.createIndex('loadTest', 'loadTest');
      }
      if (!db.objectStoreNames.contains(GROUP_STORE)) {
        db.createObjectStore(GROUP_STORE, { keyPath: 'fingerprint' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function loadState() {
  const storedGroups = await getAll(GROUP_STORE);
  for (const group of storedGroups) {
    groups.set(group.fingerprint, group);
    stats.total += group.count;
  }
}

async function reportBatch(events, batchLoadTest) {
  if (!events.length) {
    return;
  }
  const records = events.map((event) => createRecord(event, {
    occurredAt: event.occurredAt,
    userAgent: event.userAgent,
    pageUrl: event.pageUrl,
    loadTest: batchLoadTest || Boolean(event.loadTest)
  }));
  const changed = new Map();

  for (const record of records) {
    const existing = groups.get(record.fingerprint);
    if (existing) {
      addRecordToGroup(existing, record, currentNonce);
      changed.set(record.fingerprint, existing);
    } else {
      const group = createGroup(record, currentNonce);
      groups.set(record.fingerprint, group);
      changed.set(record.fingerprint, group);
    }
  }

  if (database) {
    await persistBatch(records, changed);
  }
  stats.total += records.length;
  stats.batches += 1;
  post({ type: 'STATE', groups: publicGroups(), stats: getStats() });
}

async function persistBatch(records, changedGroups) {
  return new Promise((resolve, reject) => {
    const transaction = database.transaction([RAW_STORE, GROUP_STORE], 'readwrite');
    const rawStore = transaction.objectStore(RAW_STORE);
    const groupStore = transaction.objectStore(GROUP_STORE);
    for (const record of records) {
      rawStore.put(serializeRaw(record));
    }
    for (const group of changedGroups.values()) {
      groupStore.put(group);
    }
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
  });
}

function serializeRaw(record) {
  const { source, ...raw } = record;
  return {
    ...raw,
    sourceKind: source.kind,
    origin: source.origin
  };
}

async function clear(loadTestOnly) {
  if (!loadTestOnly) {
    groups.clear();
    Object.keys(stats).forEach((key) => {
      stats[key] = 0;
    });
    if (database) {
      await clearStores([RAW_STORE, GROUP_STORE]);
    }
    return;
  }

  const raw = database ? await getAll(RAW_STORE) : [];
  const remaining = raw.filter((record) => !record.loadTest);
  groups.clear();
  stats.total = 0;
  stats.batches = 0;
  for (const record of remaining) {
    const hydrate = hydrateRecord(record);
    const existing = groups.get(hydrate.fingerprint);
    if (existing) {
      addRecordToGroup(existing, hydrate, currentNonce);
    } else {
      groups.set(hydrate.fingerprint, createGroup(hydrate, currentNonce));
    }
    stats.total += 1;
  }
  if (database) {
    await clearStores([RAW_STORE, GROUP_STORE]);
  }
  if (remaining.length) {
    if (database) {
      await persistBatch(remaining.map(hydrateRecord), groups);
    }
  }
}

function hydrateRecord(record) {
  return {
    ...record,
    source: {
      kind: record.sourceKind,
      origin: record.origin,
      file: record.sourceFile,
      path: '',
      line: record.lineNumber,
      column: record.columnNumber,
      sample: record.sample
    }
  };
}

async function clearStores(storeNames) {
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(storeNames, 'readwrite');
    for (const name of storeNames) {
      transaction.objectStore(name).clear();
    }
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
  });
}

async function sendExport(options) {
  const records = database && options.includeRaw ? (await getAll(RAW_STORE)).map(hydrateRecord) : [];
  const result = buildExport([...groups.values()], records, options);
  post({
    type: 'EXPORT_READY',
    format: result.extension,
    mimeType: result.mimeType,
    content: result.content
  });
}

function getAll(storeName) {
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(storeName, 'readonly');
    const request = transaction.objectStore(storeName).getAll();
    request.onsuccess = () => resolve(request.result || []);
    request.onerror = () => reject(request.error);
  });
}

function publicGroups() {
  return [...groups.values()];
}

function getStats() {
  return {
    ...stats,
    groupCount: groups.length,
    storedAt: new Date().toISOString()
  };
}

function post(message) {
  self.postMessage(message);
}
