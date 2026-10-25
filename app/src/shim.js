// The bridge between the page of tTerm Web and the engine of this app.
//
// The window shows the very page of tTerm Web, unchanged. That page talks to
// its core with fetch("/api/...") and one WebSocket at /api/ws. Here both go
// to the engine instead, over Tauri's IPC: no port is opened on this
// computer, so no other program and no site in a browser can reach the
// shells. The engine answers for this computer the way the core answers for
// a machine, so the page cannot tell the difference.
//
// Runs before the page's own scripts, in the window's main frame only.
(function () {
  "use strict";
  if (window.__ttermApp) return;

  // From 0.1.0 the app has the feed, and its terminals open in the line
  // mode, as on the web. The versions before it had the classic mode only
  // and kept "classic" as the page's remembered mode: forgotten once, so
  // the page starts in its own default. A choice made after that is the
  // person's, and stays.
  try {
    if (localStorage.getItem("tterm.app.feed") === null) {
      localStorage.removeItem("tterm.mode");
      localStorage.setItem("tterm.app.feed", "1");
    }
  } catch {
    // Without storage the page remembers nothing; nothing to do.
  }

  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const invoke = (cmd, args, options) =>
    window.__TAURI_INTERNALS__.invoke(cmd, args, options);

  function asBytes(result) {
    if (result instanceof ArrayBuffer) return new Uint8Array(result);
    if (ArrayBuffer.isView(result)) {
      return new Uint8Array(result.buffer, result.byteOffset, result.byteLength);
    }
    if (Array.isArray(result)) return Uint8Array.from(result);
    throw new TypeError("tTerm's engine answered something unexpected.");
  }

  async function bodyBytes(body) {
    if (body === null || body === undefined) return new Uint8Array(0);
    if (typeof body === "string") return encoder.encode(body);
    if (body instanceof ArrayBuffer) return new Uint8Array(body);
    if (ArrayBuffer.isView(body)) {
      return new Uint8Array(body.buffer.slice(body.byteOffset,
        body.byteOffset + body.byteLength));
    }
    if (body instanceof Blob) return new Uint8Array(await body.arrayBuffer());
    return encoder.encode(String(body));
  }

  // ------------------------------------------------------------- requests

  const realFetch = window.fetch.bind(window);
  window.fetch = async function (input, init) {
    const request = input instanceof Request ? input : null;
    let url;
    try {
      url = new URL(request ? request.url : String(input), location.href);
    } catch {
      return realFetch(input, init);
    }
    const ours = url.origin === location.origin &&
      (url.pathname.startsWith("/api/") || url.pathname === "/health");
    if (!ours) return realFetch(input, init);
    const method = ((init && init.method) || (request && request.method) ||
      "GET").toUpperCase();
    let body = init && "body" in init ? init.body : null;
    if ((body === null || body === undefined) && request &&
        method !== "GET" && method !== "HEAD") {
      body = await request.arrayBuffer();
    }
    // What the page asks by itself, now and then: signed in, tTerm Web
    // keeps no session on for it (from 0.3.0).
    let background = false;
    try {
      background = new Headers((init && init.headers) ||
        (request && request.headers) || undefined)
        .get("x-tterm-background") === "1";
    } catch {
      // Headers it cannot read: asked as anything else.
    }
    let raw;
    try {
      raw = asBytes(await invoke("api", await bodyBytes(body), {
        headers: { "x-tterm-method": method,
          "x-tterm-path": url.pathname + url.search,
          ...(background ? { "x-tterm-background": "1" } : {}) },
      }));
    } catch (error) {
      throw new TypeError(`tTerm's engine did not answer: ${error}`);
    }
    // Two bytes of status, one of the type's length, the type, the body.
    const status = (raw[0] << 8) | raw[1];
    const typeLength = raw[2];
    const type = decoder.decode(raw.subarray(3, 3 + typeLength));
    const content = raw.slice(3 + typeLength);
    const empty = status === 204 || status === 205 || status === 304 ||
      method === "HEAD";
    return new Response(empty ? null : content,
      { status, headers: { "content-type": type } });
  };

  // ---------------------------------------------------------------- socket

  const TEXT = 0;
  const BINARY = 1;

  // A batch: [type u8][length u32][payload], one after another. What the
  // engine sends starts with a byte of flags: 1, the engine closed it.
  function pack(messages) {
    let size = 0;
    for (const m of messages) size += 5 + m.payload.length;
    const out = new Uint8Array(size);
    const view = new DataView(out.buffer);
    let at = 0;
    for (const m of messages) {
      out[at] = m.type;
      view.setUint32(at + 1, m.payload.length);
      out.set(m.payload, at + 5);
      at += 5 + m.payload.length;
    }
    return out;
  }

  function unpack(raw) {
    const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
    const closed = (raw[0] & 1) === 1;
    const messages = [];
    let at = 1;
    while (at + 5 <= raw.length) {
      const type = raw[at];
      const length = view.getUint32(at + 1);
      messages.push({ type, payload: raw.subarray(at + 5, at + 5 + length) });
      at += 5 + length;
    }
    return { closed, messages };
  }

  const RealSocket = window.WebSocket;

  class EngineSocket extends EventTarget {
    constructor(url) {
      super();
      this.url = url;
      this.protocol = "";
      this.extensions = "";
      this.binaryType = "blob";
      this.bufferedAmount = 0;
      this.readyState = 0;
      this.onopen = null;
      this.onmessage = null;
      this.onclose = null;
      this.onerror = null;
      this._id = null;
      this._queue = [];
      this._flushing = false;
      invoke("ws_open").then((id) => {
        if (this.readyState !== 0) {
          invoke("ws_close", { id }).catch(() => {});
          return;
        }
        this._id = id;
        this.readyState = 1;
        this._fire("open", new Event("open"));
        void this._pull();
        void this._flush();
      }, () => this._end(1006, "tTerm's engine did not answer."));
    }

    _fire(type, event) {
      const handler = this["on" + type];
      if (typeof handler === "function") {
        try {
          handler.call(this, event);
        } catch (error) {
          setTimeout(() => {
            throw error;
          });
        }
      }
      this.dispatchEvent(event);
    }

    async _pull() {
      while (this.readyState === 1) {
        let raw;
        try {
          raw = asBytes(await invoke("ws_recv", { id: this._id }));
        } catch {
          this._end(1006, "tTerm's engine went away.");
          return;
        }
        const { closed, messages } = unpack(raw);
        for (const m of messages) {
          if (this.readyState !== 1) return;
          let data;
          if (m.type === TEXT) data = decoder.decode(m.payload);
          else if (this.binaryType === "arraybuffer") data = m.payload.slice().buffer;
          else data = new Blob([m.payload]);
          this._fire("message", new MessageEvent("message", { data }));
        }
        if (closed) {
          this._end(1000, "");
          return;
        }
      }
    }

    send(data) {
      if (this.readyState === 0) {
        throw new DOMException("The socket is still connecting.", "InvalidStateError");
      }
      if (this.readyState !== 1) return;
      let payload;
      if (typeof data === "string") payload = { type: TEXT, payload: encoder.encode(data) };
      else if (data instanceof ArrayBuffer) payload = { type: BINARY, payload: new Uint8Array(data.slice(0)) };
      else if (ArrayBuffer.isView(data)) {
        payload = { type: BINARY, payload: new Uint8Array(data.buffer.slice(
          data.byteOffset, data.byteOffset + data.byteLength)) };
      } else {
        throw new TypeError("This socket takes text and binary data only.");
      }
      this._queue.push(payload);
      void this._flush();
    }

    // In order, one batch at a time: two requests in flight at once could
    // reach the engine the other way round, and keys would swap.
    async _flush() {
      if (this._flushing || this._id === null) return;
      this._flushing = true;
      try {
        while (this._queue.length > 0 && this.readyState === 1) {
          const batch = this._queue.splice(0, this._queue.length);
          await invoke("ws_send", pack(batch),
            { headers: { "x-tterm-socket": String(this._id) } });
        }
      } catch {
        this._end(1006, "tTerm's engine went away.");
      } finally {
        this._flushing = false;
      }
    }

    close(code = 1000, reason = "") {
      if (this.readyState >= 2) return;
      const id = this._id;
      this._end(code, reason);
      if (id !== null) invoke("ws_close", { id }).catch(() => {});
    }

    _end(code, reason) {
      if (this.readyState === 3) return;
      this.readyState = 3;
      this._fire("close", new CloseEvent("close",
        { code, reason, wasClean: code === 1000 }));
    }
  }

  const STATES = { CONNECTING: 0, OPEN: 1, CLOSING: 2, CLOSED: 3 };
  Object.assign(EngineSocket, STATES);
  Object.assign(EngineSocket.prototype, STATES);

  function TtermWebSocket(url, protocols) {
    const address = new URL(String(url), location.href);
    if (address.pathname === "/api/ws" && address.hostname === location.hostname) {
      return new EngineSocket(address.href);
    }
    return protocols === undefined ? new RealSocket(url) : new RealSocket(url, protocols);
  }
  TtermWebSocket.prototype = RealSocket.prototype;
  Object.assign(TtermWebSocket, STATES);
  window.WebSocket = TtermWebSocket;

  // --------------------------------------------------------------- links

  // A link out of the page opens in the browser, never in this window.
  const outside = (url) => url.origin !== location.origin &&
    /^(https?|mailto):$/.test(url.protocol);

  document.addEventListener("click", (event) => {
    const link = event.target instanceof Element ? event.target.closest("a[href]") : null;
    if (!link) return;
    let url;
    try {
      url = new URL(link.href, location.href);
    } catch {
      return;
    }
    if (!outside(url)) return;
    event.preventDefault();
    invoke("open_external", { url: url.href }).catch(() => {});
  }, true);

  const realOpen = window.open;
  window.open = function (url, ...rest) {
    try {
      const address = new URL(String(url), location.href);
      if (outside(address)) {
        invoke("open_external", { url: address.href }).catch(() => {});
        return null;
      }
    } catch {
      // Not an address: as the browser would.
    }
    return realOpen.call(window, url, ...rest);
  };

  // ------------------------------------------------------------- the menu

  // What the app's menu asks of the page, done the way a click does it.
  window.__ttermApp = {
    action(name) {
      if (name === "new-terminal") {
        document.querySelector('.plus-wrap button[aria-label="New terminal"]')?.click();
      } else if (name === "close-tab") {
        document.querySelector(".tab.current .tab-close")?.click();
      }
    },
  };
})();
