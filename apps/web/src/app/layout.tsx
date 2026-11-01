import type { Metadata } from 'next';
import { Big_Shoulders, Hanken_Grotesk, JetBrains_Mono } from 'next/font/google';
import './globals.css';
import { Shell } from '@/shell/Shell';
import { CaseProvider } from '@/lib/engine';

// next/font self-hosts these at build time, so no request ever leaves for a font CDN.
const disp = Big_Shoulders({ subsets: ['latin'], weight: ['800', '900'], variable: '--font-disp', adjustFontFallback: false });
const sans = Hanken_Grotesk({ subsets: ['latin'], weight: ['400', '500', '600'], variable: '--font-sans' });
const mono = JetBrains_Mono({ subsets: ['latin'], weight: ['400', '500', '800'], variable: '--font-mono' });

// Every page is rendered per request so Next can stamp its scripts with the CSP nonce.
export const dynamic = 'force-dynamic';

export const metadata: Metadata = {
  title: 'PacketMD',
  description: 'Tells a network fault from an attack in a packet capture, with proof packets and a fix for your exact file.',
};

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" data-mode="dark" data-small="1" className={`${disp.variable} ${sans.variable} ${mono.variable}`}>
      <body><CaseProvider><Shell>{children}</Shell></CaseProvider></body>
    </html>
  );
}
