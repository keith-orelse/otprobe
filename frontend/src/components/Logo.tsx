/** OTProbe mark: a probe/radar glyph in the console's brand red. */
export function LogoMark({ size = 38 }: { size?: number }) {
  return (
    <svg className="logo-mark" width={size} height={size} viewBox="0 0 40 40" aria-hidden>
      <defs>
        <linearGradient id="otp-g" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#d02e27" /><stop offset="1" stopColor="#8a120e" />
        </linearGradient>
      </defs>
      <rect x="1" y="1" width="38" height="38" rx="11" fill="url(#otp-g)" />
      <path d="M12 26a11 11 0 0 1 16-15" fill="none" stroke="#fff" strokeOpacity=".55" strokeWidth="2.4" strokeLinecap="round" />
      <path d="M16 25.5a6 6 0 0 1 8.5-8.5" fill="none" stroke="#fff" strokeOpacity=".8" strokeWidth="2.4" strokeLinecap="round" />
      <circle cx="20" cy="22" r="3.2" fill="#fff" />
      <path d="M22.3 19.7 30 12" stroke="#fff" strokeWidth="2.4" strokeLinecap="round" />
    </svg>
  );
}

export function Logo({ subtitle = "OT discovery & probing" }: { subtitle?: string }) {
  return (
    <div className="sidebar-logo">
      <LogoMark />
      <div className="logo-text"><b>OT<span>Probe</span></b><small>{subtitle}</small></div>
    </div>
  );
}
