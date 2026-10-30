(() => {
  "use strict";
  const token = location.pathname.split("/").pop();
  const base = "/browser/console/" + encodeURIComponent(token);
  const status = document.getElementById("status");
  const image = document.getElementById("viewport");
  const controls = [...document.querySelectorAll("button, input")];
  const empty = document.getElementById("viewport-empty");
  const live = document.getElementById("connection-status");
  const updated = document.getElementById("frame-updated");
  const actionFeedback = document.getElementById("action-status");
  const address = document.getElementById("browser-address");
  const pendingCard = document.getElementById("pending-approval");
  const pendingLocation = document.getElementById("pending-location");
  const pendingMarker = document.getElementById("pending-click-marker");
  const viewportStage = document.getElementById("viewport-stage");
  let pendingRequested = false;
  function markPending(point) {
    if (!pendingMarker) return;
    if (!point || !image.naturalWidth || !viewportStage) {
      pendingMarker.hidden = true;
      return;
    }
    const rect = image.getBoundingClientRect();
    const stage = viewportStage.getBoundingClientRect();
    pendingMarker.style.left = (rect.left-stage.left+rect.width*point.x/image.naturalWidth)+"px";
    pendingMarker.style.top = (rect.top-stage.top+rect.height*point.y/image.naturalHeight)+"px";
    pendingMarker.hidden = false;
  }
  let busy = false, polling = false, hoverInFlight = false;
  let hoverTimer = null, lastHoverAt = 0;
  let touchStart = null, suppressClickUntil = 0;
  let lastHoverPoint = {x: -1, y: -1};
  let stream = null, streamReady = false, streamConnectTimeout = null;
  let pendingStreamFrame = null, streamDecoding = false;
  let streamFrameCount = 0, streamStartedAt = 0, streamLastFrameAt = 0;
  let streamFailures = 0, streamRetryAt = 0, humanFinished = false;
  const setStatus = (message, error = false) => {
    status.textContent = message;
    status.classList?.toggle("error", error);
    if (error && live) live.textContent = "Connection issue";
  };
  const setAction = (message) => {
    if (actionFeedback) actionFeedback.textContent = message;
  };
  const errorStatus = (error) => {
    const message = error?.name === "AbortError"
      ? "Browser frame timed out. The session may still be active; retry Refresh frame."
      : String(error?.message || "Browser connection unavailable");
    setStatus(message, true);
    if (empty && !image.naturalWidth) {
      empty.hidden = false;
      const heading = empty.querySelector("strong");
      if (heading) heading.textContent = "Remote image unavailable";
    }
  };
  const setBusy = (value) => {
    busy = value;
    controls.forEach((control) => { control.disabled = value; });
  };
  async function boundedFetch(path, options, timeoutMs) {
    const abort = new AbortController();
    const handle = setTimeout(() => abort.abort(), timeoutMs);
    try {
      return await fetch(path, {...options, signal:abort.signal});
    } finally {
      clearTimeout(handle);
    }
  }
  async function drawScreenshot(response) {
    if (response.status === 404) {
      humanFinished = true;
      stopStream();
      setStatus("This private handoff expired. Return to ChatGPT for a new Take control link.", true);
      throw new Error("Private handoff expired");
    }
    if (!response.ok) throw new Error("Browser session expired or unavailable");
    if (address) {
      address.textContent =
        response.headers.get("X-CommandCore-Page-Address")
        || "Remote page · address unavailable";
    }
    const blob = await response.blob();
    if (blob.type !== "image/png") {
      throw new Error("Unexpected browser screenshot format");
    }
    // Production CSP permits data: PNGs; blob: image URLs are disallowed.
    const uri = await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => typeof reader.result === "string"
        ? resolve(reader.result)
        : reject(new Error("Browser screenshot could not be read"));
      reader.onerror = () => reject(new Error("Browser screenshot could not be read"));
      reader.readAsDataURL(blob);
    });
    if (!uri.startsWith("data:image/png;base64,")) {
      throw new Error("Unexpected browser screenshot encoding");
    }
    const old = image.getAttribute("src");
    image.src = uri;
    try {
      await image.decode();
    } catch (_) {
      if (old) image.src = old;
      else image.removeAttribute("src");
      throw new Error("Browser screenshot could not be displayed");
    }
    image.hidden = false;
    if (empty) empty.hidden = true;
    if (live) live.textContent = "Live connection";
    if (updated) updated.textContent = "Frame received " + new Date().toLocaleTimeString();
    setStatus("Human control active. AI actions are paused.");
  }
  function stopStream() {
    if (streamConnectTimeout !== null) clearTimeout(streamConnectTimeout);
    streamConnectTimeout = null;
    if (stream !== null) stream.close();
    stream = null;
    streamReady = false;
    pendingStreamFrame = null;
  }
  function streamFailure(message) {
    stopStream();
    streamFailures = Math.min(streamFailures+1, 5);
    streamRetryAt = Date.now() + Math.min(60000, 10000 * (2 ** (streamFailures-1)));
    setAction(message + " · using snapshot fallback");
    if (live) live.textContent = "Snapshot fallback";
    refresh(true).catch(errorStatus);
  }
  async function displayStreamFrame() {
    if (streamDecoding) return;
    streamDecoding = true;
    try {
      while (pendingStreamFrame && stream) {
        const item = pendingStreamFrame;
        pendingStreamFrame = null;
        const uri = "data:image/png;base64," + item.png;
        const old = image.getAttribute("src");
        image.src = uri;
        try {
          await image.decode();
        } catch (_) {
          if (old) image.src = old;
          else image.removeAttribute("src");
          throw new Error("Live frame could not be decoded");
        }
        if (!stream) return;
        if (address && item.address) address.textContent = item.address;
        image.hidden = false;
        if (empty) empty.hidden = true;
        if (streamConnectTimeout !== null) clearTimeout(streamConnectTimeout);
        streamConnectTimeout = null;
        streamReady = true;
        streamFailures = 0;
        streamRetryAt = 0;
        streamFrameCount += 1;
        const now = Date.now();
        streamLastFrameAt = now;
        const elapsed = Math.max(1, now - streamStartedAt);
        const fps = Math.min(9.9, streamFrameCount * 1000 / elapsed);
        if (live) live.textContent = "Live stream · " + fps.toFixed(1) + " FPS";
        if (updated) updated.textContent =
          "Frame " + streamFrameCount + " · " + new Date(now).toLocaleTimeString();
        setStatus("Human control active. AI actions are paused.");
      }
    } catch (err) {
      streamFailure(String(err?.message || "Unable to display streamed frame"));
    } finally {
      streamDecoding = false;
    }
  }
  function startStream() {
    if (stream || humanFinished || document.hidden || typeof EventSource !== "function"
      || Date.now() < streamRetryAt) return;
    streamReady = false;
    streamFrameCount = 0;
    streamStartedAt = Date.now();
    streamLastFrameAt = 0;
    try {
      // SSE is an authenticated, same-origin, owner-only GET. The server
      // proves human handoff again before and after every Chromium capture.
      stream = new EventSource(base + "/stream", {withCredentials:true});
    } catch (_) {
      streamFailure("Live streaming unavailable");
      return;
    }
    streamConnectTimeout = setTimeout(() => {
      if (!streamReady) streamFailure("No live frame received");
    }, 12000);
    stream.addEventListener("frame", event => {
      if (!stream) return;
      try {
        const item = JSON.parse(event.data);
        if (typeof item.png !== "string"
          || item.png.length < 20 || item.png.length > 6_000_000
          || !/^[A-Za-z0-9+/=]+$/.test(item.png)
          || typeof item.address !== "string" || item.address.length > 250) {
          throw new Error("Invalid live frame");
        }
        // Backpressure: keep only the latest frame when PNG decode is slow.
        pendingStreamFrame = item;
        displayStreamFrame();
      } catch (_) {
        streamFailure("Invalid streamed frame");
      }
    });
    stream.onerror = () => {
      if (stream) streamFailure("Stream disconnected");
    };
  }
  async function refresh(force = false) {
    if (polling || (busy && !force) || (document.hidden && !force)) return;
    polling = true;
    try {
    const response = await boundedFetch(base + "/screenshot?t=" + Date.now(), {
      credentials: "same-origin", cache: "no-store"
    }, 12000);
    await drawScreenshot(response);
    } finally {polling = false;}
  }
  async function loadPending() {
    if (!pendingCard || humanFinished || pendingRequested || busy) return;
    pendingRequested = true;
    try {
      const response = await boundedFetch(base + "/action", {
        method: "POST", headers: {"Content-Type":"application/json", "Accept":"application/json"},
        credentials:"same-origin", body: JSON.stringify({name:"browser.pending",args:{}})
      }, 6000);
      if (!response.ok) { pendingCard.hidden = true; return; }
      const result = await response.json();
      const point = result?.pending;
      if (Number.isInteger(point?.x) && Number.isInteger(point?.y)) {
        pendingCard.hidden = false;
        markPending(point);
        if (pendingLocation) pendingLocation.textContent =
          "Requested position: " + point.x + ", " + point.y + ". Check the page above.";
      } else {pendingCard.hidden = true; markPending(null);}
    } catch (_) { pendingCard.hidden = true; markPending(null); }
    finally { pendingRequested = false; }
  }
  async function action(name, args = {}) {
    if (busy || humanFinished) return false;
    setBusy(true);
    setAction("Working · " + name.replace("browser.", ""));
    const started = Date.now();
    try {
      const response = await boundedFetch(base + "/action", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept": streamReady ? "application/json" : "image/png"
        },
        credentials: "same-origin",
        body: JSON.stringify({name, args})
      }, 30000);
      if (!response.ok) {
        if (response.status===403 || response.status===404) humanFinished=true;
        throw new Error("Action rejected (" + response.status + ")");
      }
      if (streamReady) {
        // Keep the authenticated stream connected through this action.
        // Its next frame will show the result without a second capture.
        await response.json();
      } else {
        await drawScreenshot(response);
      }
      setAction(name.replace("browser.", "") + " completed · " +
        (Date.now() - started) + " ms");
      return true;
    } catch (err) {
      if (err?.name === "AbortError") {
        setStatus("Action response timed out. It may have completed. Refresh the frame before retrying.", true);
        setAction("Outcome unknown · refresh before repeating");
      } else {
        errorStatus(err);
        setAction("Input not confirmed · inspect frame before retrying");
      }
      return false;
    } finally { setBusy(false); }
  }
  function pointerCoordinates(event) {
    if (image.hidden || !image.naturalWidth || !image.naturalHeight) return null;
    const rect = image.getBoundingClientRect();
    if (!rect.width || !rect.height) return null;
    const x = (event.clientX - rect.left) / rect.width;
    const y = (event.clientY - rect.top) / rect.height;
    if (x < 0 || x > 1 || y < 0 || y > 1) return null;
    return {
      // Chromium captures the actual content viewport, whose height can differ
      // from the requested worker window size (for example 1280 x 713).
      // Map the displayed image back to that capture, not a guessed 1280 x 800.
      x: Math.max(0, Math.min(image.naturalWidth - 1, Math.round(x * image.naturalWidth))),
      y: Math.max(0, Math.min(image.naturalHeight - 1, Math.round(y * image.naturalHeight)))
    };
  }
  // Hover commands are intentionally coalesced. The owner controls a real
  // Chromium input device; issuing CDP screenshots for every pointer event
  // would overload the worker and stall clicks.
  async function remoteHover(point) {
    if (busy || hoverInFlight || document.hidden) return;
    if (Date.now() - lastHoverAt < 700) return;
    if (Math.hypot(point.x - lastHoverPoint.x, point.y - lastHoverPoint.y) < 45) return;
    hoverInFlight = true;
    lastHoverAt = Date.now();
    lastHoverPoint = point;
    try {
      const response = await boundedFetch(base + "/action", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        credentials: "same-origin",
        body: JSON.stringify({name: "browser.move", args:point})
      }, 12000);
      if (!response.ok) throw new Error("Remote pointer move rejected");
    } catch (error) {
      errorStatus(error);
    } finally {
      hoverInFlight = false;
    }
  }
  image.addEventListener("pointermove", (event) => {
    if (event.pointerType !== "mouse" && event.pointerType !== "pen") return;
    if (busy || image.hidden) return;
    const point = pointerCoordinates(event);
    if (!point) return;
    if (hoverTimer !== null) clearTimeout(hoverTimer);
    hoverTimer = setTimeout(() => {
      hoverTimer = null;
      remoteHover(point);
    }, 230);
  });
  image.addEventListener("pointerleave", () => {
    if (hoverTimer !== null) clearTimeout(hoverTimer);
    hoverTimer = null;
  });
  // Touch gestures control the remote browser, not the surrounding page.
  // Tap is still mapped to click; vertical swipe sends one bounded wheel
  // action. Never synthesize a click after a completed swipe.
  image.addEventListener("touchstart", event => {
    if (event.touches.length !== 1 || busy || image.hidden) return;
    const touch = event.touches[0];
    touchStart = {x:touch.clientX,y:touch.clientY,lastY:touch.clientY};
  }, {passive:true});
  image.addEventListener("touchmove", event => {
    if (!touchStart || event.touches.length !== 1) return;
    touchStart.lastY = event.touches[0].clientY;
    if (Math.abs(touchStart.lastY-touchStart.y)>12) event.preventDefault();
  }, {passive:false});
  image.addEventListener("touchend", event => {
    if (!touchStart) return;
    const delta = touchStart.lastY-touchStart.y;
    touchStart = null;
    if (Math.abs(delta)<20 || busy || image.hidden) return;
    event.preventDefault();
    suppressClickUntil = Date.now()+650;
    const pixels = Math.max(-1000,Math.min(1000,Math.round(-delta*2)));
    if (pixels) action("browser.scroll",{delta_y:pixels});
  }, {passive:false});
  image.addEventListener("touchcancel",()=>{touchStart=null;});
  image.addEventListener("click", (event) => {
    if (Date.now()<suppressClickUntil) return;
    if (hoverTimer !== null) clearTimeout(hoverTimer);
    hoverTimer = null;
    if (busy) return;
    const point = pointerCoordinates(event);
    if (point) action("browser.click", point);
  });
  image.addEventListener("wheel", (event) => {
    if (busy || image.hidden || !image.naturalWidth || !image.naturalHeight) return;
    // Scroll the remote page rather than the surrounding console when the
    // user's mouse is over the remote Chromium viewport.
    event.preventDefault();
    const units = event.deltaMode === 1 ? event.deltaY * 16 :
      event.deltaMode === 2 ? event.deltaY * 600 : event.deltaY;
    const amount = Math.max(-1000, Math.min(1000, Math.round(units)));
    if (amount !== 0) action("browser.scroll", {delta_y:amount});
  }, {passive:false});
  document.getElementById("refresh").addEventListener("click", () => {
    refresh().catch(errorStatus);
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
  document.getElementById("approve-pending")?.addEventListener("click", async () => {
    if (!confirm("Approve the requested click at the shown position? Review the page first.")) return;
    const done = await action("browser.approve_click");
    if (done && pendingCard) { pendingCard.hidden = true; markPending(null); }
  });
  // The private console receives only a short-lived proposed coordinate.
  // The gateway revalidates the owned page and consumes approval once.
  setInterval(() => { if (!document.hidden) void loadPending(); }, 2500);
  void loadPending();
  document.getElementById("resume").addEventListener("click", async () => {
    if (busy) return;
    setBusy(true);
    stopStream();
    try {
      const grant = document.getElementById("ai-interaction-consent")?.checked === true;
      const response = await boundedFetch(base + "/resume", {
        method: "POST", credentials: "same-origin",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({allow_ai_interaction: grant}),
      }, 16000);
      if (!response.ok) throw new Error("Unable to resume agent");
      humanFinished = true;
      setStatus("Control returned to your AI client. You can close this tab.");
      if (live) live.textContent = "Returned to AI";
      if (updated) updated.textContent = "Private control ended";
      setAction(grant ? "AI controls approved on this website for 15 minutes" : "Session safely resumed");
      const field = document.getElementById("text");
      if (field) field.value = "";
      image.hidden = true;
      if (empty) empty.hidden = true;
    } catch (err) {
      if (err?.name === "AbortError") {
        setStatus("Resume response timed out. Control may have returned to AI; check ChatGPT before retrying.", true);
      } else errorStatus(err);
      setBusy(false);
    }
  });
  document.getElementById("visible-input").addEventListener("change", (event) => {
    const field = document.getElementById("text");
    field.type = event.target.checked ? "text" : "password";
  });
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      stopStream();
    } else if (!humanFinished) {
      startStream();
      if (!stream) refresh().catch(errorStatus);
    }
  });
  setInterval(() => {
    if (humanFinished) return;
    if (!document.hidden && !busy && !stream) {
      startStream();
      if (!stream) refresh().catch(errorStatus);
    }
    // A stream which stops delivering frames without closing must not
    // permanently freeze the UI. Fall back to existing authenticated GET.
    if (stream && streamReady && !document.hidden
      && Date.now()-streamLastFrameAt > 15000) {
      streamFailure("Live stream stalled");
    }
  }, 2000);

  // Capture keyboard events only while the authenticated remote viewport has
  // focus. Never register a document-wide key logger or read the clipboard.
  image.tabIndex = 0;
  image.setAttribute("aria-label", "Remote browser input. Click to type. Shift+Tab leaves the viewport.");
  image.addEventListener("pointerdown", () => {
    if (!humanFinished) image.focus({preventScroll:true});
  });
  const keyboardQueue = [];
  let keyboardTimer = null, keyboardDraining = false;
  function clearKeyboard() {
    keyboardQueue.length = 0;
    if (keyboardTimer !== null) clearTimeout(keyboardTimer);
    keyboardTimer = null;
  }
  async function drainKeyboard() {
    keyboardTimer = null;
    if (humanFinished) { clearKeyboard(); return; }
    if (keyboardDraining) return;
    if (busy) { keyboardTimer=setTimeout(drainKeyboard,40); return; }
    keyboardDraining = true;
    try {
      while (keyboardQueue.length && !humanFinished) {
        if (busy) break;
        const item=keyboardQueue.shift();
        if (!await action(item.name,item.args)) { clearKeyboard(); break; }
      }
    } finally {
      keyboardDraining=false;
      if(humanFinished) clearKeyboard();
      if (keyboardQueue.length && !humanFinished && keyboardTimer===null)
        keyboardTimer=setTimeout(drainKeyboard,40);
    }
  }
  function queueKeyboard(name,args) {
    if (humanFinished) { clearKeyboard(); return; }
    const last=keyboardQueue[keyboardQueue.length-1];
    if (name==="browser.type" && last?.name===name &&
        last.args.text.length+args.text.length<=4000) last.args.text+=args.text;
    else {
      if (keyboardQueue.length>=64) {
        clearKeyboard();
        setAction("Keyboard queue cleared: input limit reached. Inspect the page before continuing.");
        return;
      }
      keyboardQueue.push({name,args});
    }
    if (keyboardTimer===null && !keyboardDraining)
      keyboardTimer=setTimeout(drainKeyboard,35);
  }
  const directKeys=new Set(["Enter","Tab","Escape","Backspace","ArrowUp","ArrowDown","ArrowLeft","ArrowRight"]);
  image.addEventListener("keydown",event=>{
    if (humanFinished || event.isComposing || (event.key==="Tab" && event.shiftKey)) return;
    if (event.key==="F5" || ((event.ctrlKey||event.metaKey) && event.key.toLowerCase()==="r")) {
      event.preventDefault(); clearKeyboard(); action("browser.reload"); return;
    }
    if (event.ctrlKey||event.metaKey||event.altKey) return;
    if (directKeys.has(event.key)) {
      event.preventDefault();queueKeyboard("browser.keypress",{key:event.key});
    } else if (event.key.length===1) {
      event.preventDefault();queueKeyboard("browser.type",{text:event.key});
    }
  });
  // Paste is read only from the user's explicit paste event on the viewport.
  image.addEventListener("paste",event=>{
    if (humanFinished) return;
    const text=event.clipboardData?.getData("text/plain")||"";
    if (!text) return;
    event.preventDefault();
    if (text.length>4000) { setAction("Paste is limited to 4000 characters."); return; }
    queueKeyboard("browser.type",{text});
  });
  document.getElementById("refresh").innerHTML="↻ Refresh image";
  const reloadButton=document.createElement("button");
  reloadButton.id="reload-page";reloadButton.type="button";
  reloadButton.className="control-button wide-button";
  reloadButton.textContent="↻ Reload website (retry verification)";
  document.getElementById("refresh").after(reloadButton);
  controls.push(reloadButton);
  reloadButton.addEventListener("click",()=>{
    clearKeyboard();
    setAction("Reloading the actual website with fresh resources (not just the screenshot)…");
    action("browser.reload");
  });
  // Human-only, locally rendered guidance. No page content, credentials or
  // cross-origin details are sent to the AI, telemetry, or an external site.
  const help = document.createElement("details");
  help.id = "browser-login-help";
  help.className = "browser-login-help";
  const heading = document.createElement("summary");
  heading.textContent = "Verification or CAPTCHA stuck?";
  const explanation = document.createElement("p");
  explanation.textContent = "Refresh image only updates your view. Reload website requests the real login page again without clearing cookies. If a challenge hangs, retry it once, then inspect the new page before entering anything.";
  const fallback = document.createElement("p");
  fallback.textContent = "Some identity providers do not support automated or headless browser environments. If verification still fails, use your normal browser for login. CommandCore cannot copy that session or bypass the provider's challenge.";
  help.append(heading, explanation, fallback);
  reloadButton.after(help);
  const inputHint=document.querySelector(".viewer-hint");
  if(inputHint)inputHint.textContent="Click view to type · Shift+Tab to leave · Wheel to scroll";
  document.getElementById("resume").addEventListener("click",clearKeyboard);

  startStream();
  if (!stream) refresh().catch(errorStatus);
})();
