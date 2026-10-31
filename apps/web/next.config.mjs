const worker = "default-src 'none'; connect-src 'none'; script-src 'none'; base-uri 'none'";
const site = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'no-referrer' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), payment=(), usb=()' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains' },
  { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
];

export default {
  transpilePackages: ['@packetmd/core'],
  poweredByHeader: false,
  async headers() {
    return [
      { source: '/:path*', headers: site },
      // The parser's only script. Even if a hostile capture owned it, it has nowhere to send anything.
      { source: '/worker/:file*', headers: [{ key: 'Content-Security-Policy', value: worker }] },
    ];
  },
};
