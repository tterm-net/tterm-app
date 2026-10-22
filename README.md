# tTerm for your computer

tTerm Web in a window of its own, with the shells of this computer.

The window shows the very page of [tTerm Web](https://github.com/tterm-net/tterm-web),
built as it is released and unchanged but for what tTerm Web's core adds too
when it serves it: a meta tag with a one-time number for the page's own style
elements. Where that page would talk to tTerm Web's core on a server, here it
talks to the app's engine, which answers for this computer the same way: the
same requests, the same socket, the same terminals with numbered output and
replays. The shells run right here, in pseudo-terminals of this computer,
with nothing going over the network.

It has the terminals of this computer as tTerm Web has a machine's: the feed
of blocks, where each command is a block with what it printed, how long it
took and how it ended, and tTerm's own input line, with history, Tab, and a
question before a command that cannot be undone; or the classic mode, where
every key goes straight to the shell. Notes too, in folders, as in tTerm Web:
Markdown as you type, checklists, kept on this computer. No one signs in
yet, and the page shows this computer only; signing in, with the servers of
tTerm Web, and Windows come next.

## How it is made

```
engine/   Rust: the shells (pty.rs), the terminals and their pages
          (terminals.rs, socket.rs), the requests of the page (api.rs),
          the shell's markers (shell.rs), blocks and where they are kept
          (blocks.rs, store.rs), Tab (complete.rs), the question before
          a dangerous command (danger.rs), notes (notes.rs). A port of
          tterm-web's core where the page needs it to be the same.
engine/shell/
          the scripts that make bash and zsh mark their prompts and
          commands: tterm-web's own, byte for byte.
app/      Tauri: the window, the menu, the bridge (src/shim.js) that sends
          the page's requests and socket to the engine over Tauri's IPC.
web-dist/ the page of tTerm Web, put there by scripts/web.sh at the commit
          in WEB_COMMIT. Not in git.
```

**No port is opened.** The page reaches the engine only through Tauri's IPC,
and only the app's own page may: the window never loads a page from a server,
and links out of it open in the browser. No other program on the computer and
no site in a browser can reach the shells.

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

**Notes stay on this computer too,** in the same file, until you delete
them. They are kept as tTerm Web keeps notes: blocks of text, a version
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

## Building

macOS builds come from GitHub Actions (`.github/workflows/build.yml`): a disk
image with tTerm.app for Intel and Apple silicon, not signed yet. To build by
hand you need Rust, Node 22 and, on Linux, WebKitGTK 4.1:

```sh
sh scripts/web.sh                       # the page, at WEB_COMMIT
cargo test -p tterm-engine              # the engine, with real shells
cd app && npx @tauri-apps/cli@2 build   # the app
```

An app that is not signed is opened once with Open Anyway in System Settings
→ Privacy & Security, or with
`xattr -dr com.apple.quarantine /Applications/tTerm.app`.

## License

AGPL-3.0, like the rest of tTerm. See [LICENSE](LICENSE).
