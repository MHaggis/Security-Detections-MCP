import { ImageResponse } from 'next/og';

export const runtime = 'edge';

export const alt = 'Security Detections - AI-Powered Detection Coverage Intelligence';
export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';

export default function Image() {
  return new ImageResponse(
    (
      <div
        style={{
          background: 'linear-gradient(135deg, #080c0e 0%, #0f1923 40%, #111a24 100%)',
          width: '100%',
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          padding: '60px 80px',
          fontFamily: 'system-ui, sans-serif',
          position: 'relative',
          overflow: 'hidden',
        }}
      >
        {/* Grid pattern overlay */}
        <div
          style={{
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundImage:
              'linear-gradient(rgba(30, 41, 59, 0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(30, 41, 59, 0.3) 1px, transparent 1px)',
            backgroundSize: '40px 40px',
            display: 'flex',
          }}
        />

        {/* Amber glow accent */}
        <div
          style={{
            position: 'absolute',
            top: -100,
            right: -100,
            width: 400,
            height: 400,
            borderRadius: '50%',
            background: 'radial-gradient(circle, rgba(245, 158, 11, 0.15) 0%, transparent 70%)',
            display: 'flex',
          }}
        />

        {/* Shield icon */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '16px',
            marginBottom: '24px',
          }}
        >
          <svg
            width="48"
            height="48"
            viewBox="0 0 24 24"
            fill="none"
            stroke="#f59e0b"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          <span
            style={{
              color: '#f59e0b',
              fontSize: 20,
              fontWeight: 600,
              letterSpacing: '0.1em',
              textTransform: 'uppercase',
            }}
          >
            detect.michaelhaag.org
          </span>
        </div>

        {/* Title */}
        <div
          style={{
            fontSize: 64,
            fontWeight: 800,
            color: '#f8fafc',
            lineHeight: 1.1,
            marginBottom: '20px',
            display: 'flex',
          }}
        >
          Security Detections
        </div>

        {/* Subtitle */}
        <div
          style={{
            fontSize: 28,
            color: '#94a3b8',
            lineHeight: 1.4,
            marginBottom: '40px',
            display: 'flex',
          }}
        >
          AI-Powered Detection Coverage Intelligence
        </div>

        {/* Stats bar */}
        <div
          style={{
            display: 'flex',
            gap: '32px',
          }}
        >
          {[
            { label: 'Detections', value: '8,295+' },
            { label: 'Sources', value: '6' },
            { label: 'MITRE Techniques', value: '400+' },
          ].map((stat) => (
            <div
              key={stat.label}
              style={{
                display: 'flex',
                flexDirection: 'column',
                padding: '16px 24px',
                background: 'rgba(15, 25, 35, 0.8)',
                border: '1px solid #1e293b',
                borderRadius: '12px',
              }}
            >
              <span style={{ fontSize: 32, fontWeight: 700, color: '#f59e0b' }}>
                {stat.value}
              </span>
              <span style={{ fontSize: 16, color: '#64748b' }}>{stat.label}</span>
            </div>
          ))}
        </div>

        {/* Bottom border accent */}
        <div
          style={{
            position: 'absolute',
            bottom: 0,
            left: 0,
            right: 0,
            height: '4px',
            background: 'linear-gradient(90deg, #f59e0b, #38bdf8, #10b981)',
            display: 'flex',
          }}
        />
      </div>
    ),
    { ...size }
  );
}
