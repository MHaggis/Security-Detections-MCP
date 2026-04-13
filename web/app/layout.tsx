import type { Metadata } from 'next';
import { Inter, JetBrains_Mono, Bebas_Neue } from 'next/font/google';
import { Analytics } from '@vercel/analytics/next';
import './globals.css';

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-body',
  display: 'swap',
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-mono',
  display: 'swap',
});

const bebasNeue = Bebas_Neue({
  weight: '400',
  subsets: ['latin'],
  variable: '--font-display',
  display: 'swap',
});

const siteUrl = 'https://detect.michaelhaag.org';

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title: 'Security Detections | AI-Powered Detection Coverage Intelligence',
  description: 'Search 8,295+ security detections across Sigma, Splunk, Elastic, KQL, Sublime, and CrowdStrike. AI-powered coverage analysis, threat actor mapping, and gap assessment.',
  keywords: ['security detections', 'MITRE ATT&CK', 'Sigma rules', 'Splunk detections', 'threat coverage', 'detection engineering'],
  authors: [{ name: 'Michael Haag' }],
  openGraph: {
    title: 'Security Detections',
    description: 'Search 8,295+ security detections across Sigma, Splunk, Elastic, KQL, Sublime, and CrowdStrike. AI-powered coverage analysis, threat actor mapping, and gap assessment.',
    url: siteUrl,
    siteName: 'Security Detections',
    type: 'website',
    locale: 'en_US',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Security Detections',
    description: 'AI-Powered Detection Coverage Intelligence — 8,295+ detections across Sigma, Splunk, Elastic, KQL, Sublime, and CrowdStrike.',
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <body className={`${inter.variable} ${jetbrainsMono.variable} ${bebasNeue.variable} antialiased`} suppressHydrationWarning>
        {children}
        <Analytics />
      </body>
    </html>
  );
}
