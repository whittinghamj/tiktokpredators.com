<!doctype html>
<html lang="en-GB" data-cyber-watch>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="theme-color" content="#03070f">
  <meta name="color-scheme" content="dark">
  <meta name="description" content="A cinematic simulated global cyber-threat telemetry scene.">
  <title>Aegis Watch — Simulated Global Threat Telemetry</title>
  <link rel="preload" href="assets/cyber-watch/cyber-atmosphere.webp" as="image" type="image/webp" fetchpriority="high">
  <link rel="preload" href="assets/cyber-watch/world-110m.geojson" as="fetch" type="application/geo+json" crossorigin="anonymous">
  <link rel="stylesheet" href="assets/cyber-watch/cyber-watch.css">
</head>
<body class="cyber-watch-page">
  <main
    class="cyber-watch-scene"
    id="cyberWatchScene"
    data-map-url="assets/cyber-watch/world-110m.geojson"
    data-exit-url="./?view=cases#cases"
    aria-label="Aegis Watch simulated global cyber-threat display"
  >
    <div class="cyber-atmosphere" aria-hidden="true"></div>
    <div class="cyber-grid-floor" aria-hidden="true"></div>
    <div class="cyber-noise" aria-hidden="true"></div>
    <div class="cyber-vignette" aria-hidden="true"></div>

    <header class="cyber-topbar">
      <div class="cyber-brand">
        <div class="cyber-brand-mark" aria-hidden="true">
          <svg viewBox="0 0 64 64" role="img">
            <path d="M32 4 55 13v16c0 14.8-9.5 25.1-23 31C18.5 54.1 9 43.8 9 29V13L32 4Z" fill="none" stroke="currentColor" stroke-width="2.5"/>
            <path d="M22 38V25l10-6 10 6v13l-10 6-10-6Zm10-19v25M22 25l20 13M42 25 22 38" fill="none" stroke="currentColor" stroke-width="1.5" opacity=".75"/>
            <circle cx="32" cy="31.5" r="3.8" fill="currentColor"/>
          </svg>
        </div>
        <div>
          <p class="cyber-kicker">Aegis network intelligence</p>
          <h1 class="cyber-title">Global Threat Monitor</h1>
        </div>
      </div>

      <div class="cyber-topbar-status">
        <span class="cyber-sim-badge"><i aria-hidden="true"></i> Simulated telemetry</span>
        <div class="cyber-clock-block">
          <span class="cyber-clock-label">Coordinated universal time</span>
          <time class="cyber-clock" id="cyberUtcClock">00:00:00.000Z</time>
        </div>
      </div>

      <nav class="cyber-controls" aria-label="Scene controls">
        <button class="cyber-control" type="button" data-cyber-action="focus" aria-pressed="false" title="Toggle ambient focus mode (M)">
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 3H5a2 2 0 0 0-2 2v3m13-5h3a2 2 0 0 1 2 2v3M8 21H5a2 2 0 0 1-2-2v-3m13 5h3a2 2 0 0 0 2-2v-3"/></svg>
          <span>Focus</span>
        </button>
        <button class="cyber-control" type="button" data-cyber-action="fullscreen" title="Enter fullscreen (F)">
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 3H5a2 2 0 0 0-2 2v3m11-5h3a2 2 0 0 1 2 2v3M8 21H5a2 2 0 0 1-2-2v-3m11 5h3a2 2 0 0 0 2-2v-3"/></svg>
          <span>Fullscreen</span>
        </button>
        <button class="cyber-control cyber-control--exit" type="button" data-cyber-action="exit" title="Return to site (Escape)">
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M10 5H6a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h4m5-4 4-3-4-3m4 3H9"/></svg>
          <span>Exit</span>
        </button>
      </nav>
    </header>

    <section class="cyber-stage" aria-label="Animated world threat map">
      <div class="cyber-map-wrap">
        <svg id="cyberMapSvg" class="cyber-map" viewBox="0 0 1920 1080" preserveAspectRatio="none" aria-hidden="true">
          <defs>
            <linearGradient id="cyberLandGradient" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0" stop-color="#1b4d69"/>
              <stop offset=".52" stop-color="#172d4b"/>
              <stop offset="1" stop-color="#282453"/>
            </linearGradient>
            <radialGradient id="cyberMapHalo">
              <stop offset="0" stop-color="#16d9ff" stop-opacity=".2"/>
              <stop offset=".55" stop-color="#7957ff" stop-opacity=".08"/>
              <stop offset="1" stop-color="#02060d" stop-opacity="0"/>
            </radialGradient>
            <filter id="cyberMapGlow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="5" result="blur"/>
              <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
            </filter>
            <filter id="cyberLabelGlow" x="-40%" y="-100%" width="180%" height="300%">
              <feGaussianBlur in="SourceGraphic" stdDeviation="2.5" result="blur"/>
              <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
            </filter>
            <clipPath id="cyberMapClip"><rect x="92" y="146" width="1736" height="720" rx="26"/></clipPath>
          </defs>
          <ellipse cx="960" cy="515" rx="825" ry="410" fill="url(#cyberMapHalo)"/>
          <g id="cyberMapGrid" clip-path="url(#cyberMapClip)"></g>
          <g id="cyberMapCountries" clip-path="url(#cyberMapClip)"></g>
          <g class="cyber-map-labels" filter="url(#cyberLabelGlow)">
            <text class="cyber-map-label" x="435" y="307">North America</text>
            <text class="cyber-map-label" x="690" y="640">South America</text>
            <text class="cyber-map-label" x="995" y="355">Europe</text>
            <text class="cyber-map-label" x="1055" y="607">Africa</text>
            <text class="cyber-map-label" x="1400" y="405">Asia</text>
            <text class="cyber-map-label" x="1570" y="720">Oceania</text>
          </g>
        </svg>
        <canvas id="cyberThreatCanvas" class="cyber-threat-canvas" aria-hidden="true"></canvas>
        <div class="cyber-scan-sweep" id="cyberScanSweep" aria-hidden="true"></div>
        <div class="cyber-map-corner cyber-map-corner--tl" aria-hidden="true"></div>
        <div class="cyber-map-corner cyber-map-corner--tr" aria-hidden="true"></div>
        <div class="cyber-map-corner cyber-map-corner--bl" aria-hidden="true"></div>
        <div class="cyber-map-corner cyber-map-corner--br" aria-hidden="true"></div>
      </div>

      <aside class="cyber-feed-panel" aria-labelledby="cyberFeedTitle">
        <header class="cyber-panel-header">
          <div>
            <span class="cyber-panel-eyebrow">Stream 01 / rolling buffer</span>
            <h2 id="cyberFeedTitle">Synthetic Event Feed</h2>
          </div>
          <span class="cyber-live-pill"><i></i> Live</span>
        </header>
        <div class="cyber-feed-rule" aria-hidden="true"><span></span></div>
        <ol class="cyber-event-list" id="cyberEventList" aria-live="off" aria-label="Simulated cyber events">
          <li class="cyber-event cyber-event--placeholder">Establishing synthetic telemetry stream…</li>
        </ol>
        <p class="cyber-feed-disclaimer">Demonstration data only. No events, organisations, people, or source locations shown here are real.</p>
      </aside>

      <section class="cyber-status-card" aria-label="Current simulated threat status">
        <div class="cyber-status-item">
          <span class="cyber-status-label">Threat posture</span>
          <strong class="cyber-status-value" id="cyberThreatLevel">Elevated</strong>
        </div>
        <div class="cyber-status-item">
          <span class="cyber-status-label">Mesh integrity</span>
          <strong class="cyber-status-value">99.982%</strong>
        </div>
        <div class="cyber-threat-meter" aria-hidden="true"><span id="cyberThreatMeter"></span></div>
        <div class="cyber-status-item">
          <span class="cyber-status-label">Avg response</span>
          <strong class="cyber-status-value" id="cyberResponseTime">18.4 ms</strong>
        </div>
        <div class="cyber-status-item">
          <span class="cyber-status-label">Packets / sec</span>
          <strong class="cyber-status-value" id="cyberPacketRate">2.81M</strong>
        </div>
      </section>
    </section>

    <section class="cyber-bottom-dock" aria-label="Simulated totals and event legend">
      <div class="cyber-metric cyber-metric--primary">
        <span class="cyber-metric-label">Events analysed</span>
        <strong class="cyber-metric-value" id="cyberTotalEvents">8,492,116</strong>
      </div>
      <div class="cyber-metric is-green">
        <span class="cyber-metric-label">Threats blocked</span>
        <strong class="cyber-metric-value" id="cyberBlockedEvents">8,471,834</strong>
      </div>
      <div class="cyber-metric is-magenta">
        <span class="cyber-metric-label">Active routes</span>
        <strong class="cyber-metric-value" id="cyberActiveRoutes">00</strong>
      </div>
      <div class="cyber-metric is-violet">
        <span class="cyber-metric-label">Nodes online</span>
        <strong class="cyber-metric-value" id="cyberNodesOnline">1,482</strong>
      </div>
      <div class="cyber-legend" aria-label="Event type legend">
        <span class="cyber-legend-item"><i class="cyber-legend-swatch"></i><span>Probe</span></span>
        <span class="cyber-legend-item"><i class="cyber-legend-swatch"></i><span>Malware</span></span>
        <span class="cyber-legend-item"><i class="cyber-legend-swatch"></i><span>Exploit</span></span>
        <span class="cyber-legend-item"><i class="cyber-legend-swatch"></i><span>Blocked</span></span>
      </div>
    </section>

    <div class="cyber-ticker" aria-hidden="true">
      <div class="cyber-ticker-track">
        <span class="cyber-ticker-item">Simulation engine nominal</span>
        <span class="cyber-ticker-item">Global sensor mesh synchronised</span>
        <span class="cyber-ticker-item">Documentation IP space active</span>
        <span class="cyber-ticker-item">Zero real-world telemetry</span>
        <span class="cyber-ticker-item">Map / Natural Earth · public domain</span>
        <span class="cyber-ticker-item">Simulation engine nominal</span>
        <span class="cyber-ticker-item">Global sensor mesh synchronised</span>
        <span class="cyber-ticker-item">Documentation IP space active</span>
        <span class="cyber-ticker-item">Zero real-world telemetry</span>
        <span class="cyber-ticker-item">Map / Natural Earth · public domain</span>
      </div>
    </div>

    <div class="cyber-loading" id="cyberLoading" role="status">
      <div class="cyber-loading-mark" aria-hidden="true"><span></span><span></span><span></span></div>
      <p>Synchronising global mesh</p>
    </div>

    <div class="cyber-rotate-prompt" role="status">
      <svg viewBox="0 0 64 64" aria-hidden="true"><rect x="17" y="8" width="30" height="48" rx="4"/><path d="M9 24A25 25 0 0 1 27 4M9 24l-3-9m3 9 9-3"/></svg>
      <strong>Landscape display</strong>
      <span>Rotate your device for the full Cyber Watch scene.</span>
    </div>

    <p class="cyber-a11y-status" id="cyberA11yStatus" aria-live="polite">Loading simulated telemetry display.</p>
  </main>

  <noscript><div class="cyber-noscript">This animated scene needs JavaScript enabled.</div></noscript>
  <script src="assets/cyber-watch/cyber-watch.js"></script>
</body>
</html>
