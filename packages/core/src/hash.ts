// Own hashes: MD5 for JA3-style fingerprints, streaming SHA-256 because subtle.digest cannot stream.
const rol = (x: number, n: number) => (x << n) | (x >>> (32 - n));

const MD5_S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
const MD5_K = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0);

export function md5(text: string): string {
  const src = new TextEncoder().encode(text);
  const n = ((src.length + 8) >> 6) + 1;
  const w = new Uint32Array(n * 16);
  src.forEach((b, i) => { w[i >> 2]! |= b << ((i % 4) * 8); });
  w[src.length >> 2]! |= 0x80 << ((src.length % 4) * 8);
  w[n * 16 - 2] = src.length * 8;
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  for (let o = 0; o < w.length; o += 16) {
    let a = a0, b = b0, c = c0, d = d0;
    for (let i = 0; i < 64; i++) {
      const r = i >> 4;
      const f = r === 0 ? (b & c) | (~b & d) : r === 1 ? (d & b) | (~d & c) : r === 2 ? b ^ c ^ d : c ^ (b | ~d);
      const g = r === 0 ? i : r === 1 ? (5 * i + 1) % 16 : r === 2 ? (3 * i + 5) % 16 : (7 * i) % 16;
      const t = d; d = c; c = b;
      b = (b + rol((a + f + MD5_K[i]! + w[o + g]!) | 0, MD5_S[r * 4 + (i % 4)]!)) | 0;
      a = t;
    }
    a0 = (a0 + a) | 0; b0 = (b0 + b) | 0; c0 = (c0 + c) | 0; d0 = (d0 + d) | 0;
  }
  return [a0, b0, c0, d0].map((x) => { const v = new DataView(new ArrayBuffer(4)); v.setUint32(0, x, true); return v.getUint32(0).toString(16).padStart(8, '0'); }).join('');
}

const K = new Uint32Array(64);
{
  let n = 0;
  for (let c = 2; n < 64; c++) {
    let prime = true;
    for (let d = 2; d * d <= c; d++) if (c % d === 0) { prime = false; break; }
    if (prime) K[n++] = ((Math.cbrt(c) % 1) * 2 ** 32) >>> 0;
  }
}
const ror = (x: number, n: number) => (x >>> n) | (x << (32 - n));

export class Sha256 {
  h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  buf = new Uint8Array(64);
  fill = 0;
  total = 0;
  w = new Uint32Array(64);

  private block(b: Uint8Array, o: number) {
    const w = this.w, h = this.h;
    for (let i = 0; i < 16; i++) w[i] = (b[o + i * 4]! << 24) | (b[o + i * 4 + 1]! << 16) | (b[o + i * 4 + 2]! << 8) | b[o + i * 4 + 3]!;
    for (let i = 16; i < 64; i++) {
      const a = w[i - 15]!, c = w[i - 2]!;
      w[i] = (w[i - 16]! + (ror(a, 7) ^ ror(a, 18) ^ (a >>> 3)) + w[i - 7]! + (ror(c, 17) ^ ror(c, 19) ^ (c >>> 10))) | 0;
    }
    let [a, b1, c, d, e, f, g, i0] = h as unknown as number[];
    for (let i = 0; i < 64; i++) {
      const t1 = (i0! + (ror(e!, 6) ^ ror(e!, 11) ^ ror(e!, 25)) + ((e! & f!) ^ (~e! & g!)) + K[i]! + w[i]!) | 0;
      const t2 = ((ror(a!, 2) ^ ror(a!, 13) ^ ror(a!, 22)) + ((a! & b1!) ^ (a! & c!) ^ (b1! & c!))) | 0;
      i0 = g; g = f; f = e; e = (d! + t1) | 0; d = c; c = b1; b1 = a; a = (t1 + t2) | 0;
    }
    h[0]! += a!; h[1]! += b1!; h[2]! += c!; h[3]! += d!; h[4]! += e!; h[5]! += f!; h[6]! += g!; h[7]! += i0!;
  }

  update(b: Uint8Array) {
    this.total += b.length;
    let p = 0;
    if (this.fill) {
      const n = Math.min(64 - this.fill, b.length);
      this.buf.set(b.subarray(0, n), this.fill);
      this.fill += n; p = n;
      if (this.fill === 64) { this.block(this.buf, 0); this.fill = 0; }
    }
    for (; p + 64 <= b.length; p += 64) this.block(b, p);
    if (p < b.length) { this.buf.set(b.subarray(p), 0); this.fill = b.length - p; }
  }

  digest(): string {
    const bits = this.total * 8, f = this.fill;
    const pad = new Uint8Array((f < 56 ? 64 : 128) - f);
    pad[0] = 0x80;
    const dv = new DataView(pad.buffer);
    dv.setUint32(pad.length - 8, Math.floor(bits / 2 ** 32));
    dv.setUint32(pad.length - 4, bits >>> 0);
    this.update(pad);
    return Array.from(this.h, (x) => x.toString(16).padStart(8, '0')).join('');
  }
}
