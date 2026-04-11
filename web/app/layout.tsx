import type { Metadata } from 'next';
import { Inter, JetBrains_Mono, Bebas_Neue } from 'next/font/google';
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

export const metadata: Metadata = {
  title: 'Security Detections | AI-Powered Detection Coverage Intelligence',
  description: 'Search 8,295+ security detections across Sigma, Splunk, Elastic, KQL, Sublime, and CrowdStrike. AI-powered coverage analysis, threat actor mapping, and gap assessment.',
  keywords: ['security detections', 'MITRE ATT&CK', 'Sigma rules', 'Splunk detections', 'threat coverage', 'detection engineering'],
  authors: [{ name: 'Michael Haag' }],
  openGraph: {
    title: 'Security Detections',
    description: 'AI-Powered Detection Coverage Intelligence',
    type: 'website',
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
      </body>
    </html>
  );
}
