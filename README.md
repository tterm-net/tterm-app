# tTerm for your computer

tTerm Web in a window of its own, with the shells of this computer.

The window shows the very page of [tTerm Web](https://github.com/tterm-net/tterm-web),
built as it is released and unchanged but for what tTerm Web's core adds too
when it serves it: a meta tag with a one-time number for the page's own style
elements. Where that page would talk to tTerm Web's core on a server, here it
talks to the app's engine, which answers for this computer the same way: the
same requests, the same socket, the same terminals with numbered output and
replays. The shells run right here, in pseudo-terminals of this computer,
and what they print never goes over the network.

It has the terminals of this computer as tTerm Web has a machine's: the feed
of blocks, where each command is a block with what it printed, how long it
took and how it ended, and tTerm's own input line, with history, Tab, and a
question before a command that cannot be undone; or the classic mode, where
every key goes straight to the shell. Notes too, in folders, as in tTerm Web:
Markdown as you type, checklists. Before signing in the page shows this
computer only, and notes are kept on it. Signed in to tTerm Web (from 0.3.0),
the window has the person's servers, projects and notes as tTerm Web has
them, and this computer is a machine of theirs in Personal, marked as the
one the window runs on. Search (from 0.3.1), Cmd+K, finds the commands of
every terminal, what they printed and notes: this computer's in the app
itself, the rest in tTerm Web, as one list. Windows comes later.

## How it is made

```
engine/   Rust: the shells (pty.rs), the terminals and their pages
          (terminals.rs, socket.rs), the requests of the page (api.rs),
          the shell's markers (shell.rs), blocks and where they are kept
          (blocks.rs, store.rs), Tab (complete.rs), the question before
          a dangerous command (danger.rs), notes (notes.rs), search
          (search.rs). A port of tterm-web's core where the page needs it
          to be the same.
          With the cloud feature (the app's): signing in with the browser
          (account.rs, loopback.rs), the page's requests to tTerm Web
          (cloud_api.rs, upstream.rs), its cloud terminals over the socket
          (upstream_socket.rs). The link to tTerm Web (link.rs, proxy.rs)
          and the terminals tTerm Web opens through it (hosted.rs).
agent/    tterm-agent: the engine without a window, connecting a computer
          to tTerm Web (see below).
engine/shell/
          the scripts that make bash and zsh mark their prompts and
          commands: tterm-web's own, byte for byte.
app/      Tauri: the window, the menu, the bridge (src/shim.js) that sends
          the page's requests and socket to the engine over Tauri's IPC,
          the device's key in the keychain (src/keychain.rs).
web-dist/ the page of tTerm Web, put there by scripts/web.sh at the commit
          in WEB_COMMIT. Not in git.
```

**No port is opened** for the shells. The page reaches the engine only
through Tauri's IPC, and only the app's own page may: the window never loads
a page from a server, and links out of it open in the browser. No other
program on the computer and no site in a browser can reach the shells.

**Signing in goes through the browser,** as RFC 8252 says an app should.
Sign in with your browser opens `app.tterm.net/connect`; the person signs in
there, checks that the browser shows the same code as the app, and presses
Allow. The browser then brings a one-time code to a port of 127.0.0.1 that
the app opens for those minutes only, and answers nothing else on; the app
trades the code, with a secret that never left it (RFC 7636), for a key of
its own. The key is in the keychain: item "tTerm", account `app.tterm.net`.
Until the app is signed by Apple, each new version is another program to the
keychain, and the Mac asks for the password once; Always Allow keeps it so.
The app is then a device in Settings → Devices of tTerm Web, and Forget there
signs it out. Sign out in the app forgets it too.

**This computer is the same machine as for its agent.** tTerm Web knows a
computer by its own key, in `~/.tterm-web/env`, which tTerm Web's agent keeps:
the app shows tTerm that key once signed in, and if there is no such file
writes one in the agent's format, so that an agent set up later is this same
computer. Its terminals in the window run here; those opened on it from
tTerm Web in a browser run through the agent, as before.

**Without a connection the app works on** with this computer: tTerm's part
of the window is what it said last, grey, and comes back by itself. What the
app keeps of the account, besides the key, is in its folder, for the person
alone: who signed in (`account.json`) and tTerm's last answer
(`cloud-state.json`).

**The shell goes at the pace of the window,** as in a terminal: a shell that
writes faster than the window draws waits for it, so Ctrl+C on a flood takes
at once and little is left to scroll by. A window that stops taking output,
hidden or gone, holds the shell back for two seconds at most; one still
drawing what it has, for ten.

**The shell marks its commands,** as on the web: bash and zsh start with
tterm-web's scripts (engine/shell; scripts/web.sh checks they are the same
files), which mark where each prompt and each command begins with a one-time
key, and the engine takes the marks out before anything is drawn. The
scripts live in the app's own folder (on a Mac
`~/Library/Application Support/net.tterm.desktop/shell`), not in `~/.tterm`,
where tterm-agent keeps those of tTerm Web. Without bash or zsh, or with a
bash older than 4.4, terminals work in the classic mode only.

**Commands stay on this computer.** Each finished command is kept in the
app's folder, readable by you alone: its text, folder and branch, its code,
and what it printed, the beginning and the end of it if it was long. They
stay 30 days, as on the web by default, and the feed of a terminal that has
ended, or of one from before the app was last quit, is still there.

**Search finds them here** (from 0.3.1), as tTerm Web's core finds its own:
the words in any order and any case, a word inside another too, in the
command or in what it printed, kept as plain text beside it (the start and
the end of a long output); the commands of a terminal from before 0.3.1 get
theirs in the background. Signed in, the question goes to tTerm Web as well,
and the page gets one list: a command on a machine once, the latest first.
Without a connection, this computer's alone. A photo set in tTerm Web shows
in the window too: the page fetches it through the app, which carries
pictures as pictures.

**Notes made before signing in stay on this computer too,** in the same
file, until you delete them, or sign in: then they go to Personal in tTerm
Web, folder by folder, each deleted here once it is there. They are kept as
tTerm Web keeps notes: blocks of text, a version
with every change, two tabs' changes merged block by block and a question
only where both changed the same block, and who ticked an item and when. A
note saved is on the disk before the page says Saved. If the file is ever
damaged, the app keeps it aside, starts a new one and says so; while it
cannot open its file at all, it takes no notes rather than lose them.

**Shells as a login gives them.** The login shell runs as a login shell, in a
clean environment made the way sshd makes one, with a UTF-8 locale. Closing a
terminal hangs it up, as closing a window does; a shell that ignores that is
killed three seconds later. Quitting the app asks first when shells would end,
and names the commands running: from the menu, the window, the Dock, or at
log out. Nothing of the app's own is left open in a shell.

## The agent

`tterm-agent` connects a computer to tTerm Web, so that its terminals open
there: a Mac, or a Linux machine at home with no screen. It is this engine
without the window, one file of a few megabytes with nothing to install
around it, and it takes the place of agent.py from
[tterm-agent](https://github.com/tterm-net/tterm-agent) for tTerm Web (the
Telegram bot keeps agent.py). Its numbers go on from agent.py's: 0.14.0 is
the first.

**It dials out.** A laptop has no address to reach it at, sits behind NAT
and sleeps, so the agent opens the connection itself, over TLS (the roots
built in, and the system's own), and keeps it: a sign of life every 20
seconds, a sleep noticed by the clocks, a dead link dropped and dialled
again, every 3 seconds while there is no network. No port is opened on the
computer. It never runs as root. Behind a company's proxy it goes through
it, as agent.py did: `https_proxy` and `no_proxy`, or on a Mac the proxy in
System Settings (http:// proxies, with CONNECT).

**Terminals outlive a dropped link.** The laptop sleeps, the Wi-Fi blinks:
the shells go on, the last megabyte of what each printed is kept, and tTerm
Web takes each terminal back from the byte it has, for an hour while the
computer is awake without the link.

**It is a pipe.** It starts the shells tTerm Web asks for and passes their
bytes both ways, and runs the short `sh` scripts tTerm Web sends (Tab, the
folders and branches over the input line, the passport, the scripts of the
markers). The markers, the blocks and the history live in tTerm Web, as for
a server.

**Settings.** tTerm Web's installer (Add a machine, then Computer) keeps
them in `~/.tterm-web/env`, for you only: `TTERM_HUB`, `TTERM_TOKEN`,
`TTERM_KEY`, the computer's own key, made on it and sent only to that tTerm
Web, and maybe `TTERM_NAME`. A computer removed in tTerm Web hears it, ends
its terminals, forgets the key and stays stopped. By hand, with the token
from the same dialog:

```sh
TTERM_TOKEN=... tterm-agent --hub wss://connect.tterm.net/agent
```

Its log lines are agent.py's: `connected as «name»`, `link alive: …`,
`no network …`, `access revoked: …`.

**It updates itself,** when an installer put it in place: a few minutes
after it starts and every six hours after, it looks at tTerm's releases
here, and takes a newer version only when `tterm-agent.json`, the list of
the files with their sizes and checksums, carries a signature that checks
against the key built into it (`agent/release-key.pub`, never to change:
agents out there know only that one), and the file against that list. The
private half of the key is only in this repository's secrets, for the
release build. GitHub is reached as tTerm Web is, with the same TLS and
through the same proxy. A new version goes in only while no terminal is
open on the computer, so as not to end anyone's work, and only once it has
said its version when asked; the agent then starts again as it in the same
process, and keeps the one before as `tterm-agent.old`. The new version is
on trial until it has connected and stayed up ten minutes: one that stops
three times, cannot start with its settings, or does not connect in fifteen
minutes goes, the one before comes back, and that version is not taken
again (`tterm-agent.skip`). A release made a pre-release or deleted is no
longer taken, by agents waiting for their terminals to close too. GitHub
can hold a new version back, never make one up. `TTERM_UPDATE=off` in its
settings turns this off; an agent started by hand never updates itself.

The files come from GitHub Actions (`.github/workflows/agent.yml`): macOS
(Intel and Apple silicon in one), Linux on Intel and AMD, Linux on ARM,
both linked statically. A tag `agent-vX.Y.Z` makes a release of them,
with the signed `tterm-agent.json` and `SHA256SUMS`.

## Building

macOS builds come from GitHub Actions (`.github/workflows/build.yml`): a disk
image with tTerm.app for Intel and Apple silicon, not signed yet. To build by
hand you need Rust, Node 22 and, on Linux, WebKitGTK 4.1:

```sh
sh scripts/web.sh                       # the page, at WEB_COMMIT
cargo test -p tterm-engine --features cloud
                                        # the engine, with real shells
cargo test -p tterm-agent               # the agent
cargo build --release -p tterm-agent    # the agent: target/release/tterm-agent
cd app && npx @tauri-apps/cli@2 build   # the app
```

An app that is not signed is opened once with Open Anyway in System Settings
→ Privacy & Security, or with
`xattr -dr com.apple.quarantine /Applications/tTerm.app`.

## License

AGPL-3.0, like the rest of tTerm. See [LICENSE](LICENSE).
