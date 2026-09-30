// PortalGuard app: everything on screen is drawn from the engine's progress
// feed (docs/feed.md), one event at a time. The app never touches the
// firewall; it starts `portalguard arm -json` and reads what it says.
//
// In the app, the Go side (gui/app.go) is window.go.main.App and delivers
// events on "feed". Opened in a plain browser, it replays a real armed login
// instead: index.html?demo, or ?demo&at=12 to stop after 12 events.

(() => {
  const $ = (sel) => document.querySelector(sel);
  const app = $('.app');
  const el = {
    pill: $('[data-pill]'),
    glyph: $('[data-glyph]'),
    headline: $('[data-headline]'),
    sub: $('[data-sub]'),
    context: $('[data-context]'),
    steps: $('[data-steps]'),
    primary: $('[data-primary]'),
    hint: $('[data-hint]'),
    arc: $('.ring-arc'),
  };

  const GLYPHS = {
    shield: '<path d="M12 2.5 4.5 5.4v6.1c0 4.8 3.2 8.4 7.5 10 4.3-1.6 7.5-5.2 7.5-10V5.4z"/>',
    lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
    wifi: '<path d="M2.5 9a14 14 0 0 1 19 0M5.5 12.5a9.5 9.5 0 0 1 13 0M8.5 16a5 5 0 0 1 7 0"/><circle cx="12" cy="19.5" r="0.6"/>',
    key: '<circle cx="8" cy="15" r="4"/><path d="m11 12 8.5-8.5M16 7l2.5 2.5M14 9l2 2"/>',
    seal: '<path d="M12 2.5 4.5 5.4v6.1c0 4.8 3.2 8.4 7.5 10 4.3-1.6 7.5-5.2 7.5-10V5.4z"/><path d="m8.6 12.2 2.4 2.4 4.6-4.9"/>',
    tunnel: '<path d="M4 20V11a8 8 0 0 1 16 0v9"/><path d="M8.5 20v-8a3.5 3.5 0 0 1 7 0v8"/>',
    home: '<path d="m3.5 11 8.5-7 8.5 7"/><path d="M6 9.5V20h12V9.5"/>',
    alert: '<path d="M12 3 2.5 20h19z"/><path d="M12 10v4.5M12 17.4v.1"/>',
  };
  const STEPS = ['armed', 'network', 'login', 'sealed', 'vpn'];

  // ==== state =============================================================

  let st;
  function reset() {
    st = {
      phase: 'idle',
      step: -1,
      host: '',
      url: '',
      opened: [],
      suggest: [],
      summary: null,
      vpnName: '',
      vpnIface: '',
      note: '',
      error: '',
      trusted: '',
      wait: '',
      doctor: st ? st.doctor : null,
    };
  }
  reset();

  // apply folds one feed event into the state.
  function apply(ev) {
    switch (ev.type) {
      case 'start':
        reset();
        st.phase = 'armed';
        st.step = 0;
        break;
      case 'waiting':
        st.wait = ev.for;
        if (ev.for === 'vpn') {
          st.phase = 'vpn';
          st.step = 4;
          st.vpnName = ev.starting || '';
        }
        break;
      case 'transition':
        transition(ev);
        break;
      case 'login_url':
        st.url = ev.url;
        break;
      case 'suggest':
        st.suggest = ev.names || [];
        break;
      case 'note':
        st.note = ev.text;
        break;
      case 'trusted':
        st.phase = 'trusted';
        st.trusted = ev.label;
        st.step = -1;
        break;
      case 'summary':
        st.summary = ev;
        break;
      case 'vpn':
        st.vpnIface = ev.interface;
        break;
      case 'done':
        if (ev.cancelled) {
          const doctor = st.doctor;
          reset();
          st.doctor = doctor;
          st.note = 'Cancelled. Your network is back.';
          break;
        }
        if (st.phase !== 'trusted') {
          st.phase = ev.state === 'HANDED_OFF' ? 'done' : 'sealedwait';
          st.step = ev.state === 'HANDED_OFF' ? 5 : 4;
        }
        st.wait = '';
        break;
      case 'error':
        st.phase = 'error';
        st.error = ev.text;
        st.wait = '';
        break;
    }
  }

  function transition(ev) {
    switch (ev.to) {
      case 'ARMED':
        st.phase = 'armed';
        st.step = 0;
        break;
      case 'LOCKED_DOWN':
        st.step = 1;
        if (ev.event === 'PORTAL_FOUND') {
          st.host = ev.note;
          st.phase = 'locked';
        } else if (ev.event === 'NO_PORTAL') {
          st.phase = 'locked';
          st.host = '';
        }
        break;
      case 'GAP_OPEN':
        st.phase = 'login';
        st.step = 2;
        st.wait = 'login';
        if (ev.event === 'EXTEND_GAP') {
          const host = ev.note.split(' (')[0];
          if (!st.opened.includes(host)) st.opened.push(host);
          st.suggest = st.suggest.filter((n) => n !== host);
        }
        break;
      case 'AUTHENTICATED':
        st.phase = 'signedin';
        st.step = 3;
        st.wait = '';
        break;
      case 'SEALED':
        st.phase = 'sealed';
        st.step = 3;
        break;
      case 'IDLE':
        if (st.phase !== 'trusted' && ev.event === 'RELEASE') st.step = -1;
        break;
    }
  }

  // ==== drawing ===========================================================

  const COPY = {
    starting: ['Starting', 'lock', 'Starting', 'Enter your Mac password to let PortalGuard control the firewall.'],
    idle: ['Ready', 'shield', 'Ready when you are', 'Arm before you join public Wi-Fi. Nothing on this Mac can reach the network until you have signed in and your VPN is up.'],
    armed: ['Armed', 'wifi', 'Join the Wi-Fi now', 'Everything on this Mac is blocked, so nothing leaks while it connects.'],
    locked: ['Locked', 'lock', 'Checking this network', 'Only PortalGuard’s own checks can get out.'],
    login: ['Sign in', 'key', 'Sign in on the page that opened', 'Only the login page can get through. Every other app stays blocked.'],
    signedin: ['Signed in', 'seal', 'You’re signed in', 'Closing the gap behind you.'],
    sealed: ['Sealed', 'seal', 'Sealed', 'The gap is closed. Only your VPN may connect now.'],
    sealedwait: ['Sealed', 'seal', 'Connect your VPN', 'Traffic stays blocked until it is up.'],
    vpn: ['VPN', 'tunnel', 'Starting your VPN', 'Until its tunnel is up, only VPN traffic can leave.'],
    done: ['Protected', 'seal', 'You’re protected', ''],
    trusted: ['Home', 'home', 'Trusted network', ''],
    error: ['Stopped', 'alert', 'Something stopped it', ''],
  };

  let shownGlyph = '';
  function draw() {
    const [pill, glyph, headline, sub] = COPY[st.phase];
    app.dataset.phase = st.phase === 'sealedwait' ? 'vpn' : st.phase;
    if (st.wait) app.dataset.wait = st.wait;
    else delete app.dataset.wait;

    el.pill.textContent = pill;
    if (glyph !== shownGlyph) {
      el.glyph.innerHTML = GLYPHS[glyph];
      shownGlyph = glyph;
    }
    let h = headline;
    let s = sub;
    if (st.phase === 'locked' && st.host) {
      h = 'Found a login page';
      s = st.host;
    } else if (st.phase === 'vpn') {
      h = st.vpnName ? `Starting ${st.vpnName}` : 'Connect your VPN now';
    } else if (st.phase === 'done') {
      s = st.vpnIface ? `Your VPN is up on ${st.vpnIface}. PortalGuard has stepped aside.` : 'PortalGuard has stepped aside.';
    } else if (st.phase === 'trusted') {
      s = `This is ${st.trusted}. PortalGuard stood down.`;
    } else if (st.phase === 'error') {
      s = st.error;
    }
    if (el.headline.textContent !== h) {
      el.headline.textContent = h;
      el.headline.style.animation = 'none';
      void el.headline.offsetWidth; // restart the sheen on a new headline
      el.headline.style.animation = '';
    }
    el.sub.textContent = s;

    // The ring fills with progress through the five steps.
    const frac = st.phase === 'done' || st.phase === 'trusted' ? 1 : Math.max(0, (st.step + 1) / 5);
    el.arc.style.setProperty('--offset', String(327 * (1 - frac)));

    el.steps.querySelectorAll('li').forEach((li, i) => {
      li.classList.toggle('done', i < st.step || st.phase === 'done');
      li.classList.toggle('now', i === st.step && st.phase !== 'done' && st.phase !== 'error');
    });
    el.steps.style.setProperty('--progress', String(Math.max(0, Math.min(st.step, 4)) / 4));
    el.steps.style.visibility = st.phase === 'trusted' ? 'hidden' : '';

    drawContext();
    drawActions();
  }

  function drawContext() {
    const parts = [];
    if (st.phase === 'login' && st.url) {
      parts.push(`<button class="link" data-open-url>
        <svg viewBox="0 0 24 24"><path d="M14 4h6v6M20 4l-9 9M19 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h5"/></svg>
        <span>Didn’t open? Open the login page<small>${esc(st.url)}</small></span></button>`);
    }
    if (st.opened.length && ['login', 'signedin', 'sealed'].includes(st.phase)) {
      parts.push(`<div class="label">Opened automatically</div>
        <div class="chips">${st.opened.map((h) => `<span class="chip"><b>+</b>${esc(h)}</span>`).join('')}</div>`);
    }
    if (st.suggest.length && st.phase === 'login') {
      parts.push(`<div class="label">The page may also need</div>` +
        st.suggest.map((n) => `<div class="ask"><span>${esc(n)}</span><button data-allow="${esc(n)}">Open</button></div>`).join(''));
    }
    if (st.summary && (st.phase === 'done' || st.phase === 'sealedwait' || st.phase === 'vpn')) {
      const s = st.summary;
      parts.push(`<div class="label">While you signed in</div><div class="stats">
        <div class="stat"><b data-count="${s.blocked_out_packets || 0}">0</b><span>packets held back</span></div>
        <div class="stat"><b data-count="${s.lookups_refused || 0}">0</b><span>lookups kept on this Mac</span></div>
        <div class="stat"><b data-count="${Math.round(s.gap_seconds || 0)}" data-suffix="s">0s</b><span>the gap was open</span></div>
      </div>`);
    }
    if (st.phase === 'idle' && st.doctor) {
      // doctor, as this user: what would stop a run, before one starts.
      const rows = st.doctor.filter((f) => f.title !== 'the firewall was not checked').slice(0, 6);
      parts.push(`<div class="label">This Mac</div><ul class="checks">${rows
        .map((f) => `<li class="lvl-${esc(f.level)}"><i></i><span>${esc(cap(f.title))}</span></li>`)
        .join('')}</ul>`);
    }
    if (st.note && st.phase !== 'done') parts.push(`<p class="note">${esc(st.note)}</p>`);
    const html = parts.join('');
    if (html !== el.context.dataset.html) {
      el.context.dataset.html = html;
      el.context.innerHTML = html;
      countUp();
    }
  }

  function drawActions() {
    const running = !['idle', 'done', 'trusted', 'error'].includes(st.phase);
    el.primary.disabled = st.phase === 'starting';
    el.primary.textContent = running ? 'Cancel' : st.phase === 'idle' ? 'Arm' : 'Arm again';
    el.primary.className = running ? 'btn btn--quiet' : 'btn btn--primary';
    el.hint.textContent = running
      ? 'Cancel releases everything and gives the network back.'
      : 'You will be asked for your Mac password.';
  }

  function countUp() {
    el.context.querySelectorAll('[data-count]').forEach((b) => {
      const to = Number(b.dataset.count);
      const suffix = b.dataset.suffix || '';
      const t0 = performance.now();
      const tick = (t) => {
        const k = Math.min(1, (t - t0) / 900);
        b.textContent = Math.round(to * (1 - Math.pow(1 - k, 3))) + suffix;
        if (k < 1) requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    });
  }

  function cap(s) {
    return s.charAt(0).toUpperCase() + s.slice(1);
  }

  function esc(s) {
    return String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
  }

  // ==== the engine, or a replay of it ===================================

  const engine = window.go && window.go.main && window.go.main.App;

  function onEvent(ev) {
    apply(ev);
    draw();
  }

  el.primary.addEventListener('click', () => {
    const running = !['idle', 'done', 'trusted', 'error'].includes(st.phase);
    if (st.phase === 'starting') return;
    if (engine) {
      if (running) engine.Cancel();
      else {
        const doctor = st.doctor;
        reset();
        st.doctor = doctor;
        st.phase = 'starting';
        draw();
        engine.Arm().catch((e) => {
          const text = String(e);
          if (text.includes('password prompt')) {
            st.phase = 'idle';
            st.note = 'Not armed: the password prompt was closed.';
            draw();
          } else {
            onEvent({ type: 'error', text });
          }
        });
      }
    } else if (!running) {
      demo();
    }
  });
  el.context.addEventListener('click', (e) => {
    const allow = e.target.closest('[data-allow]');
    if (allow && engine) engine.Open(allow.dataset.allow);
    if (e.target.closest('[data-open-url]') && engine) engine.OpenURL(st.url);
  });

  if (engine) {
    window.runtime.EventsOn('feed', onEvent);
    const refresh = () =>
      engine
        .Doctor()
        .then((fs) => {
          st.doctor = fs;
          if (st.phase === 'idle') draw();
        })
        .catch(() => {});
    refresh();
    window.addEventListener('focus', refresh);
  }

  // A real armed login, from the feed of a hotspot run, with a payment host
  // on another site added so every part of the screen appears.
  const REPLAY = [
    [0, { type: 'start', command: 'arm' }],
    [600, { type: 'transition', from: 'IDLE', event: 'ARM', to: 'ARMED', note: 'pf' }],
    [300, { type: 'waiting', for: 'network' }],
    [3200, { type: 'transition', from: 'ARMED', event: 'PORTAL_FOUND', to: 'LOCKED_DOWN', note: 'www.btwifi.com' }],
    [1600, { type: 'transition', from: 'LOCKED_DOWN', event: 'OPEN_GAP', to: 'GAP_OPEN', note: 'www.btwifi.com' }],
    [100, { type: 'login_url', url: 'http://www.btwifi.com:8443/login' }],
    [100, { type: 'waiting', for: 'login' }],
    [900, { type: 'transition', from: 'GAP_OPEN', event: 'EXTEND_GAP', to: 'GAP_OPEN', note: 'cdn.btwifi.com (same site, automatic)' }],
    [700, { type: 'transition', from: 'GAP_OPEN', event: 'EXTEND_GAP', to: 'GAP_OPEN', note: 'reg.btwifi.com (same site, automatic)' }],
    [900, { type: 'suggest', names: ['secure.worldpay.com'] }],
    [3500, { type: 'transition', from: 'GAP_OPEN', event: 'AUTHENTICATED', to: 'AUTHENTICATED' }],
    [900, { type: 'transition', from: 'AUTHENTICATED', event: 'SEAL', to: 'SEALED' }],
    [100, { type: 'summary', gap_seconds: 6, blocked_out_packets: 524, lookups_refused: 91 }],
    [300, { type: 'waiting', for: 'vpn', starting: 'My VPN' }],
    [2600, { type: 'vpn', status: 'up', interface: 'utun4' }],
    [100, { type: 'done', state: 'HANDED_OFF' }],
  ];

  let timers = [];
  function demo(upTo) {
    timers.forEach(clearTimeout);
    timers = [];
    reset();
    draw();
    if (upTo !== undefined) {
      REPLAY.slice(0, upTo).forEach(([, ev]) => apply(ev));
      draw();
      return;
    }
    let t = 0;
    for (const [dt, ev] of REPLAY) {
      t += dt;
      timers.push(setTimeout(() => onEvent(ev), t));
    }
  }

  const DEMO_DOCTOR = [
    { level: 'ok', title: 'network: default route on en0 via 192.168.0.1' },
    { level: 'ok', title: 'the portalguard anchor is in /etc/pf.conf' },
    { level: 'ok', title: "the DNS filter's ports are free (53530, 41053)" },
    { level: 'ok', title: 'this network is trusted (home): arm stands down here' },
    { level: 'ok', title: 'the handover starts your VPN: "My VPN"' },
    { level: 'info', title: 'NordVPN is installed' },
  ];

  const q = new URLSearchParams(location.search);
  if (!engine) st.doctor = DEMO_DOCTOR;
  if (!engine && q.has('demo')) {
    demo(q.has('at') ? Number(q.get('at')) : undefined);
  } else {
    draw();
  }
})();
