(function () {
  const TOKEN_KEY = "aegis_dash_token";
  let token = localStorage.getItem(TOKEN_KEY) || "";
  let lastFetch = 0;

  const loginView = document.getElementById("view-login");
  const mainView = document.getElementById("view-main");
  const loginForm = document.getElementById("login-form");
  const loginError = document.getElementById("login-error");

  function authHeaders() {
    const h = { "Content-Type": "application/x-www-form-urlencoded" };
    if (token) h["Authorization"] = "Bearer " + token;
    return h;
  }

  async function api(path, opts) {
    const res = await fetch(path, Object.assign({ credentials: "same-origin" }, opts || {}, {
      headers: Object.assign(authHeaders(), (opts && opts.headers) || {})
    }));
    if (res.status === 401) {
      token = "";
      localStorage.removeItem(TOKEN_KEY);
      showLogin();
      throw new Error("unauthorized");
    }
    return res.json();
  }

  function showLogin() {
    loginView.hidden = false;
    mainView.hidden = true;
  }
  function showMain() {
    loginView.hidden = true;
    mainView.hidden = false;
    refreshAll();
  }

  loginForm.addEventListener("submit", async function (e) {
    e.preventDefault();
    loginError.hidden = true;
    const password = document.getElementById("password").value;
    try {
      const data = await api("/api/dashboard/login", {
        method: "POST",
        body: "password=" + encodeURIComponent(password)
      });
      if (!data.ok) throw new Error("login failed");
      token = data.token;
      localStorage.setItem(TOKEN_KEY, token);
      document.getElementById("password").value = "";
      showMain();
    } catch (err) {
      loginError.textContent = "Sign-in failed. Check the dashboard token.";
      loginError.hidden = false;
    }
  });

  document.getElementById("btn-logout").addEventListener("click", function () {
    token = "";
    localStorage.removeItem(TOKEN_KEY);
    fetch("/api/dashboard/logout", { method: "POST", credentials: "same-origin" });
    showLogin();
  });

  document.querySelectorAll(".tab").forEach(function (btn) {
    btn.addEventListener("click", function () {
      document.querySelectorAll(".tab").forEach(function (b) { b.classList.remove("active"); });
      btn.classList.add("active");
      document.querySelectorAll(".tab-panel").forEach(function (p) { p.hidden = true; });
      document.getElementById("tab-" + btn.dataset.tab).hidden = false;
    });
  });

  function card(label, value) {
    return '<div class="card"><div class="label">' + label + '</div><div class="value">' + value + '</div></div>';
  }

  async function refreshOverview() {
    const data = await api("/api/dashboard/overview");
    const s = data.stats || {};
    document.getElementById("overview-cards").innerHTML = [
      card("Total", s.total || 0),
      card("Active (OK)", s.active_ok || 0),
      card("Revoked", s.revoked || 0),
      card("Suspended", s.suspended || 0),
      card("Expired (OK past date)", s.expired_ok_rows || 0),
      card("Unbound", s.unbound || 0),
      card("Lifetime plan rows", s.lifetime || 0)
    ].join("");
    lastFetch = Date.now();
    document.getElementById("overview-updated").textContent = "Updated " + new Date(lastFetch).toLocaleTimeString();
    document.getElementById("stale-badge").hidden = true;
  }

  async function refreshLicences(q) {
    const data = await api("/api/dashboard/licences?q=" + encodeURIComponent(q || ""));
    const list = document.getElementById("licence-list");
    const detail = document.getElementById("licence-detail");
    detail.hidden = true;
    list.innerHTML = (data.licences || []).map(function (r) {
      return '<button type="button" class="row" data-serial="' + r.serial + '">' +
        '<div class="serial">' + r.serial + '</div>' +
        '<div><span class="status ' + r.status + '">' + r.status + '</span> · ' + r.plan + ' · exp ' + r.expiry + '</div>' +
        '</button>';
    }).join("") || '<p class="muted">No licences found.</p>';
    list.querySelectorAll(".row").forEach(function (btn) {
      btn.addEventListener("click", async function () {
        const d = await api("/api/dashboard/licences/" + encodeURIComponent(btn.dataset.serial));
        detail.hidden = false;
        detail.innerHTML = "<h3>Licence detail</h3><pre>" + JSON.stringify(d.licence, null, 2) + "</pre>" +
          '<p class="muted">Issue/revoke only via admin CLI — not from this dashboard.</p>';
      });
    });
  }

  document.getElementById("search-form").addEventListener("submit", function (e) {
    e.preventDefault();
    refreshLicences(document.getElementById("q").value);
  });

  async function refreshHealth() {
    const data = await api("/api/dashboard/health");
    document.getElementById("health-body").innerHTML = [
      card("DB OK", data.db_ok ? "yes" : "no"),
      card("DB path", data.db_path || "—"),
      card("Uptime (sec)", data.uptime_sec || 0),
      card("Public healthz", data.licence_health_url || "—")
    ].join("");
  }

  async function refreshAll() {
    try {
      await refreshOverview();
      await refreshLicences("");
      await refreshHealth();
    } catch (e) {
      if (lastFetch) document.getElementById("stale-badge").hidden = false;
    }
  }

  // boot
  if (token) showMain();
  else showLogin();
  setInterval(function () {
    if (!mainView.hidden) refreshAll();
  }, 8000);
})();
