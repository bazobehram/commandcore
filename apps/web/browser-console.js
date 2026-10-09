(() => {
  "use strict";
  const token = location.pathname.split("/").pop();
  const base = "/browser/console/" + encodeURIComponent(token);
  const status = document.getElementById("status");
  const image = document.getElementById("viewport");
  const controls = [...document.querySelectorAll("button, input")];
  let busy = false;
  const setStatus = (message) => { status.textContent = message; };
  const setBusy = (value) => {
    busy = value;
    controls.forEach((control) => { control.disabled = value; });
  };
  async function refresh() {
    const response = await fetch(base + "/screenshot?t=" + Date.now(), {
      credentials: "same-origin", cache: "no-store"
    });
    if (!response.ok) throw new Error("Browser session expired or unavailable");
    const blob = await response.blob();
    const old = image.dataset.objectUrl;
    const uri = URL.createObjectURL(blob);
    image.src = uri;
    image.dataset.objectUrl = uri;
    if (old) URL.revokeObjectURL(old);
    setStatus("Human control active. AI actions are paused.");
  }
  async function action(name, args = {}) {
    if (busy) return;
    setBusy(true);
    try {
      const response = await fetch(base + "/action", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({name, args})
      });
      if (!response.ok) throw new Error("Action rejected (" + response.status + ")");
      await refresh();
    } catch (err) { setStatus(err.message); }
    finally { setBusy(false); }
  }
  image.addEventListener("click", (event) => {
    if (busy || !image.naturalWidth || !image.naturalHeight) return;
    const rect = image.getBoundingClientRect();
    const x = Math.round((event.clientX - rect.left) * image.naturalWidth / rect.width);
    const y = Math.round((event.clientY - rect.top) * image.naturalHeight / rect.height);
    action("browser.click", {x, y});
  });
  document.getElementById("refresh").addEventListener("click", () => {
    refresh().catch((err) => setStatus(err.message));
  });
  document.getElementById("scroll-up").addEventListener("click", () => {
    action("browser.scroll", {delta_y: -500});
  });
  document.getElementById("scroll-down").addEventListener("click", () => {
    action("browser.scroll", {delta_y: 500});
  });
  document.getElementById("send-text").addEventListener("click", () => {
    const field = document.getElementById("text");
    if (field.value) action("browser.type", {text: field.value});
    field.value = "";
  });
  for (const key of ["enter", "tab", "escape"]) {
    document.getElementById(key).addEventListener("click", () => {
      action("browser.keypress", {key: key[0].toUpperCase() + key.slice(1)});
    });
  }
  document.getElementById("resume").addEventListener("click", async () => {
    if (busy) return;
    setBusy(true);
    try {
      const response = await fetch(base + "/resume", {
        method: "POST", credentials: "same-origin"
      });
      if (!response.ok) throw new Error("Unable to resume agent");
      setStatus("Control returned to your AI client. You can close this tab.");
      image.hidden = true;
    } catch (err) { setStatus(err.message); setBusy(false); }
  });
  refresh().catch((err) => setStatus(err.message));
})();
