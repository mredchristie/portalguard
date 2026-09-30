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
    pin: '<path d="M12 21s-6.5-5.6-6.5-11a6.5 6.5 0 0 1 13 0c0 5.4-6.5 11-6.5 11z"/><circle cx="12" cy="10" r="2.3"/>',
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
      noPassword: st ? st.noPassword : false,
      scan: st ? st.scan : null,
      selected: st ? st.selected : '',
      // Kept across the engine's own reset on "start": set when arming, and
      // needed after Cancel. Wiped, the app never tried to rejoin.
      returnTo: st ? st.returnTo : '',
      password: '',
      joining: '',
      others: [],
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
      case 'joining':
        st.joining = ev.ssid;
        st.joinedSaved = !!ev.was_saved;
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
      case 'refused':
        // Another site the page may be waiting on; payment ones first.
        if (!st.others.some((o) => o.name === ev.name) && !st.opened.includes(ev.name)) {
          st.others.push({ name: ev.name, kind: ev.kind });
          st.others.sort((a, b) => (a.kind === 'payment' ? 0 : 1) - (b.kind === 'payment' ? 0 : 1));
        }
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
          const { doctor, returnTo } = st;
          reset();
          st.doctor = doctor;
          st.note = 'Cancelled. Your network is back.';
          goBack(returnTo);
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
          st.others = st.others.filter((o) => o.name !== host);
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
    idle: ['Ready', 'wifi', 'Choose a network', 'PortalGuard locks this Mac first, then joins it for you, so nothing leaks while it connects.'],
    armed: ['Armed', 'lock', 'Join the Wi-Fi now', 'Everything on this Mac is blocked, so nothing leaks while it connects.'],
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
    if (st.phase === 'armed' && st.joining) {
      h = `Joining ${st.joining}`;
    } else if (st.phase === 'locked' && st.host) {
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
    app.classList.toggle('is-idle', st.phase === 'idle');

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
    if (st.others.length && st.phase === 'login') {
      parts.push(`<div class="label">Other sites the page may need</div>
        <p class="quiet small">Open one only if the page is stuck on it, such as a payment step.</p>` +
        st.others.slice(0, 6).map((o) => `<div class="ask"><span>${esc(o.name)}${o.kind === 'payment' ? ' <em class="tag tag--pay">Payment</em>' : ''}</span><button data-allow="${esc(o.name)}">Open</button></div>`).join(''));
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
    if (st.phase === 'idle') parts.push(networksHTML());
    if (st.note && st.phase !== 'done') parts.push(`<p class="note">${esc(st.note)}</p>`);
    const html = parts.join('');
    const typing = document.activeElement && document.activeElement.matches('[data-pw]');
    if (html !== el.context.dataset.html && !typing) {
      el.context.dataset.html = html;
      el.context.innerHTML = html;
      countUp();
    }
  }

  // networksHTML is the idle screen's list, or why there is no list.
  function networksHTML() {
    const sc = st.scan;
    let body = '';
    if (!sc) {
      body = `<p class="quiet">Looking for networks…</p>`;
    } else if (sc.error && !(sc.networks || []).length) {
      body = `<p class="quiet">${esc(cap(sc.error))}</p>`;
    } else if (!sc.power) {
      body = `<p class="quiet">Wi-Fi is off. Turn it on in the menu bar, and networks will appear here.</p>`;
    } else if (sc.location === 'ask' || (sc.location !== 'allowed' && !(sc.networks || []).length)) {
      const denied = sc.location === 'denied' || sc.location === 'restricted';
      body = `<div class="permit">
        <svg viewBox="0 0 24 24">${GLYPHS.pin}</svg>
        <div><b>See the networks around you</b>
        <span>macOS shows Wi-Fi names only to apps with Location. PortalGuard uses it for that alone, and never records where you are.</span>
        ${denied
          ? `<button class="mini" data-open-location>Open Location settings</button>`
          : `<button class="mini" data-ask-location>Allow Location</button>`}</div></div>`;
    } else {
      const rows = (sc.networks || []).map((n) => {
        const sel = n.ssid === st.selected;
        const bars = n.rssi >= -55 ? 4 : n.rssi >= -65 ? 3 : n.rssi >= -75 ? 2 : 1;
        const tags = (n.current ? '<em class="tag">Connected</em>' : '') +
          (n.open ? '<em class="tag tag--open">Open</em>' : '<svg class="lockic" viewBox="0 0 24 24">' + GLYPHS.lock + '</svg>');
        // The network the Mac is already on is not joined again, so it needs
        // no password; any other secured one does.
        const pw = sel && !n.open && !n.current
          ? `<input class="pw" type="password" placeholder="Password" data-pw autocomplete="off" />`
          : '';
        return `<li class="net${sel ? ' sel' : ''}" data-ssid="${esc(n.ssid)}" tabindex="0">
          <span class="bars b${bars}"><i></i><i></i><i></i><i></i></span>
          <span class="ssid">${esc(n.ssid)}</span>${tags}${pw}</li>`;
      }).join('');
      body = `<ul class="nets">${rows || '<li class="quiet">No networks in range.</li>'}</ul>` +
        (sc.hidden ? `<p class="quiet small">${sc.hidden} more without a name.</p>` : '');
    }
    return `<div class="label row"><span>Networks nearby</span><button class="refresh" data-refresh title="Scan again">↻</button></div>${body}${doctorLine()}`;
  }

  // doctorLine is doctor's verdict in one line: ready, or the first problem.
  function doctorLine() {
    if (!st.doctor) return '';
    const bad = st.doctor.find((f) => f.level === 'fail') || st.doctor.find((f) => f.level === 'warn');
    const lvl = bad ? bad.level : 'ok';
    const text = bad ? cap(bad.title) : 'This Mac is ready';
    const detail = bad && bad.detail ? ` title="${esc(bad.detail)}"` : '';
    return `<p class="doc lvl-${lvl}"${detail}><i></i>${esc(text)}</p>`;
  }

  function selectedNetwork() {
    return ((st.scan && st.scan.networks) || []).find((n) => n.ssid === st.selected);
  }

  function drawActions() {
    const running = !['idle', 'done', 'trusted', 'error'].includes(st.phase);
    el.primary.disabled = st.phase === 'starting' || (st.phase === 'idle' && !st.selected);
    if (st.phase === 'idle') {
      const n = selectedNetwork();
      el.primary.textContent = !st.selected
        ? 'Choose a network'
        : n && n.current
          ? `Arm on ${st.selected}`
          : `Arm and join ${st.selected}`;
      el.primary.className = 'btn btn--primary';
      el.hint.innerHTML = '<button class="textlink" data-arm-any>Arm without choosing</button> · ' + (st.noPassword ? 'no password needed' : 'you will be asked for your Mac password');
      return;
    }
    el.primary.textContent = running ? 'Cancel' : st.phase === 'error' ? 'Give the network back' : 'Back to networks';
    el.primary.className = running ? 'btn btn--quiet' : 'btn btn--primary';
    el.hint.textContent = running
      ? 'Cancel releases everything and gives the network back.'
      : st.noPassword ? 'No password needed: the PortalGuard helper is installed.' : 'You will be asked for your Mac password.';
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

  function arm(ssid) {
    const n = selectedNetwork();
    if (ssid && n && !n.open && !n.current && !st.password) {
      st.note = `${ssid} is secured: type its password first.`;
      draw();
      const pw = el.context.querySelector('[data-pw]');
      if (pw) pw.focus();
      return;
    }
    // Already on it: nothing to join, just lock and check it.
    const join = n && n.current ? '' : ssid;
    const doctor = st.doctor;
    const scan = st.scan;
    const password = st.password;
    reset();
    Object.assign(st, { doctor, scan, selected: ssid, phase: 'starting' });
    draw();
    // Where to come back to: the network the Mac was on when armed.
    st.returnTo = join && st.scan && st.scan.current && st.scan.current !== join ? st.scan.current : '';
    engine.Arm(join, join ? password : '').catch((e) => {
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

  el.primary.addEventListener('click', () => {
    const running = !['idle', 'done', 'trusted', 'error'].includes(st.phase);
    if (st.phase === 'starting') return;
    if (engine && st.phase === 'idle') {
      if (st.selected) arm(st.selected);
      return;
    }
    if (engine && st.phase === 'error') {
      // The engine stops with the lockdown in place (it fails closed), and
      // has exited: releasing takes a fresh password prompt.
      el.primary.disabled = true;
      engine
        .Release()
        .then(() => {
          goBack();
          backToNetworks();
          st.note = 'The network is back, and this Mac is rejoining your usual Wi-Fi.';
          draw();
        })
        .catch((e) => {
          el.primary.disabled = false;
          st.error = `${st.error}\n\nReleasing failed: ${e}`;
          draw();
        });
      return;
    }
    if (engine && !running) {
      backToNetworks();
      return;
    }
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
  el.hint.addEventListener('click', (e) => {
    if (e.target.closest('[data-arm-any]')) {
      if (engine) arm('');
      else demo();
    }
  });
  el.context.addEventListener('input', (e) => {
    if (e.target.matches('[data-pw]')) st.password = e.target.value;
  });
  el.context.addEventListener('click', (e) => {
    const row = e.target.closest('[data-ssid]');
    if (row && !e.target.matches('[data-pw]')) {
      const ssid = row.dataset.ssid;
      if (st.selected !== ssid) {
        st.selected = ssid;
        st.password = '';
        st.note = '';
        draw();
        const pw = el.context.querySelector('[data-pw]');
        if (pw) pw.focus();
      }
    }
    if (e.target.closest('[data-refresh]')) scan();
    if (e.target.closest('[data-ask-location]') && engine) {
      engine.AskLocation();
      // macOS answers in its own time; look again as it does.
      let n = 0;
      const t = setInterval(() => {
        scan();
        if (++n > 15 || (st.scan && st.scan.location !== 'ask')) clearInterval(t);
      }, 1000);
    }
    if (e.target.closest('[data-open-location]') && engine) {
      engine.OpenURL('x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices');
    }
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
    engine.HelperInstalled().then((yes) => {
      st.noPassword = yes;
      draw();
    });
    scan();
    // Networks come and go: look again every so often while choosing.
    setInterval(() => {
      if (st.phase === 'idle') scan();
    }, 8000);
  }

  // goBack rejoins the network the Mac was on before arming, if it left one.
  // The first time, macOS asks whether PortalGuard may use its saved
  // password: Always Allow, and it does not ask again.
  function goBack(to) {
    const ssid = to !== undefined ? to : st.returnTo;
    if (!engine || !ssid) return;
    st.note = `Rejoining ${ssid}…`;
    draw();
    engine
      .Rejoin(ssid)
      .then(() => {
        st.note = `Back on ${ssid}.`;
        draw();
        setTimeout(scan, 3000);
      })
      .catch((e) => {
        st.note = `Could not rejoin ${ssid} (${e}). Choose it from the Wi-Fi menu.`;
        draw();
      });
  }

  function backToNetworks() {
    const { doctor, scan: sc, selected } = st;
    reset();
    Object.assign(st, { doctor, scan: sc, selected });
    draw();
    scan();
  }

  function scan() {
    if (!engine) return;
    engine.Networks().then((sc) => {
      st.scan = sc;
      if (st.selected && !(sc.networks || []).some((n) => n.ssid === st.selected)) st.selected = '';
      if (st.phase === 'idle') draw();
    });
  }

  // A real armed login, from the feed of a hotspot run, with a payment host
  // on another site added so every part of the screen appears.
  const REPLAY = [
    [0, { type: 'start', command: 'arm' }],
    [600, { type: 'transition', from: 'IDLE', event: 'ARM', to: 'ARMED', note: 'pf' }],
    [100, { type: 'joining', ssid: 'BTWi-fi' }],
    [300, { type: 'waiting', for: 'network' }],
    [3200, { type: 'transition', from: 'ARMED', event: 'PORTAL_FOUND', to: 'LOCKED_DOWN', note: 'www.btwifi.com' }],
    [1600, { type: 'transition', from: 'LOCKED_DOWN', event: 'OPEN_GAP', to: 'GAP_OPEN', note: 'www.btwifi.com' }],
    [100, { type: 'login_url', url: 'http://www.btwifi.com:8443/login' }],
    [100, { type: 'waiting', for: 'login' }],
    [900, { type: 'transition', from: 'GAP_OPEN', event: 'EXTEND_GAP', to: 'GAP_OPEN', note: 'cdn.btwifi.com (same site, automatic)' }],
    [700, { type: 'transition', from: 'GAP_OPEN', event: 'EXTEND_GAP', to: 'GAP_OPEN', note: 'reg.btwifi.com (same site, automatic)' }],
    [900, { type: 'refused', name: 'secure.worldpay.com', kind: 'payment' }],
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
    // ?pick: start on the list with that network chosen, as a person would.
    let t = q.has('pick') ? 2600 : 0;
    for (const [dt, ev] of REPLAY) {
      t += dt;
      timers.push(setTimeout(() => onEvent(ev), t));
    }
    // ?loop: play it again, for a page that shows the app running.
    if (q.has('loop')) timers.push(setTimeout(() => demo(), t + 5000));
  }

  const DEMO_DOCTOR = [
    { level: 'ok', title: 'network: default route on en0 via 192.168.0.1' },
    { level: 'ok', title: 'the portalguard anchor is in /etc/pf.conf' },
    { level: 'ok', title: "the DNS filter's ports are free (53530, 41053)" },
    { level: 'ok', title: 'this network is trusted (home): arm stands down here' },
    { level: 'ok', title: 'the handover starts your VPN: "My VPN"' },
    { level: 'info', title: 'NordVPN is installed' },
  ];

  const DEMO_SCAN = {
    location: 'allowed',
    power: true,
    current: 'Christie Home',
    hidden: 2,
    networks: [
      { ssid: 'Christie Home', rssi: -41, open: false, current: true },
      { ssid: 'BTWi-fi', rssi: -52, open: true },
      { ssid: 'EE WiFi', rssi: -58, open: true },
      { ssid: 'Harbour Hotel Guest', rssi: -66, open: true },
      { ssid: 'SKY9F3A2', rssi: -71, open: false },
      { ssid: 'BT-7XJQ2K', rssi: -79, open: false },
    ],
  };

  const q = new URLSearchParams(location.search);
  if (!engine) {
    st.doctor = DEMO_DOCTOR;
    st.scan = q.has('ask') ? { location: 'ask', power: true, networks: [] } : DEMO_SCAN;
    if (q.has('pick')) st.selected = q.get('pick');
  }
  if (!engine && q.has('demo')) {
    demo(q.has('at') ? Number(q.get('at')) : undefined);
  } else {
    draw();
  }
})();
