// SPDX-License-Identifier: AGPL-3.0-or-later
// P4: named-stream (xattr) storage on the namespace store — CRUD, updated_seq
// bumps, cascade delete, and AAPL readdir enrichment.

import { env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { filespaceDoName } from "../src/security/auth";
import { NamespaceStore } from "../src/metadata/namespace";

const ORG = "org-streams";

async function withNs<T>(space: string, fn: (ns: NamespaceStore) => T | Promise<T>): Promise<T> {
  const stub = (env as any).FILESPACE.get(
    (env as any).FILESPACE.idFromName(filespaceDoName(ORG, space)),
  );
  return runInDurableObject(stub, async (_i: unknown, state: DurableObjectState) =>
    fn(new NamespaceStore(state.storage.sql)),
  );
}

describe("item_streams CRUD", () => {
  it("puts, lists, gets, and deletes a stream", async () => {
    await withNs("crud", async (ns) => {
      const item = ns.put("root", "clip.mov", false, 10);
      const data = new Uint8Array([1, 2, 3, 4, 5]);

      expect(ns.putStream(item.id, "com.apple.metadata:kMDItemWhereFroms", data)).toEqual({ size: 5 });
      const list = ns.listStreams(item.id);
      expect(list).toEqual([{ name: "com.apple.metadata:kMDItemWhereFroms", size: 5 }]);

      const got = ns.getStream(item.id, "com.apple.metadata:kMDItemWhereFroms");
      expect(got && Array.from(got)).toEqual([1, 2, 3, 4, 5]);

      expect(ns.deleteStream(item.id, "com.apple.metadata:kMDItemWhereFroms")).toBe(true);
      expect(ns.listStreams(item.id)).toEqual([]);
      expect(ns.deleteStream(item.id, "gone")).toBe(false);
    });
  });

  it("bumps the item's updated_seq on stream mutation", async () => {
    await withNs("seq", async (ns) => {
      const item = ns.put("root", "f", false, 0);
      const before = ns.getItem(item.id)!.updatedSeq;
      ns.putStream(item.id, "AFP_Resource", new Uint8Array([9]));
      const after = ns.getItem(item.id)!.updatedSeq;
      expect(after).toBeGreaterThan(before);
    });
  });

  it("returns null putting a stream on a missing item", async () => {
    await withNs("missing", async (ns) => {
      expect(ns.putStream("ino-does-not-exist", "AFP_Resource", new Uint8Array([1]))).toBeNull();
    });
  });

  it("cascade-deletes streams when the item is deleted", async () => {
    await withNs("cascade", async (ns) => {
      const item = ns.put("root", "doomed", false, 0);
      ns.putStream(item.id, "AFP_Resource", new Uint8Array([1, 2]));
      ns.remove(item.id);
      expect(ns.listStreams(item.id)).toEqual([]);
    });
  });

  it("enriches items with rsrcForkSize and finderInfo from streams", async () => {
    await withNs("enrich", async (ns) => {
      const item = ns.put("root", "img.psd", false, 100);
      ns.putStream(item.id, "AFP_Resource", new Uint8Array(2048)); // 2 KiB resource fork
      // AfpInfo: 60-byte blob, FinderInfo (32 bytes) at offset 16.
      const afp = new Uint8Array(60);
      for (let i = 0; i < 32; i++) afp[16 + i] = i + 1;
      ns.putStream(item.id, "AFP_AfpInfo", afp);

      const items = [ns.getItem(item.id)!];
      ns.enrichStreams(items);
      expect(items[0].rsrcForkSize).toBe(2048);
      const envelope = atob(items[0].finderInfoCiphertext as string);
      expect(envelope.length).toBe(60);
      expect(envelope.charCodeAt(16)).toBe(1);
      expect(envelope.charCodeAt(47)).toBe(32);
      expect(items[0].finderInfo).toBeUndefined();
    });
  });
});
