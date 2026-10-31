import { openSync, readSync, statSync, closeSync } from 'node:fs';
import type { ByteSource } from '@packetmd/core';

export function fileSource(path: string): ByteSource & { close(): void } {
  const fd = openSync(path, 'r'), size = statSync(path).size;
  return {
    size,
    async read(off, len) {
      const n = Math.min(len, size - off), b = new Uint8Array(Math.max(0, n));
      if (n > 0) readSync(fd, b, 0, n, off);
      return b;
    },
    close: () => closeSync(fd),
  };
}
