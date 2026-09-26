# Local forensic findings

The evidence is the preserved filesystem in `evidence/` and the memory image
`C:/Users/Admin/Downloads/dist/mem.raw`. Times below are UTC unless stated.

## Unauthorized miner

- Volatility identifies process 7161 (`kworker1`, UID 1000), started
  2026-09-05 18:05:15. Its executable mapping is `/tmp/kworker1 (deleted)`.
- Recovered Bash history shows `chmod +x kworker1`,
  `nohup ./kworker1 > out 2>&1 &`, a process check, and `rm -rf kworker1`.
  The operator also removed `/tmp/VMwareDnD/` and
  `/home/centos/.cache/vmware/`. Stale locate entries identify a VMware
  drag-and-drop copy at
  `/home/centos/.cache/vmware/drag_and_drop/Veaq64/kworker1`.
- The in-memory ELF is `namqb 6.26.0`, a rebranded XMRig 6.26.0 build. Its
  embedded configuration specifies coin `XMR`, pool `172.24.106.17:3333`,
  worker `worker-7f3a91c2`, token `tok_4d9c67e2a15b`, TLS disabled,
  donation level zero, and maximum thread hint 100.
- Process 7161 had an ESTABLISHED TCP connection from
  `192.168.76.131:37416` to `172.24.106.17:3333` at capture. Standard
  output was redirected to `/tmp/out`; its recovered contents show attempts
  to load `/tmp/config.json`, `/home/centos/.namqb.json`, and
  `/home/centos/.config/namqb.json`. Those attempts failed, consistent with
  the embedded configuration.
- The reconstructed process ELF is
  `recovered/pid.7161.kworker1.0x55c2d17fe000.dmp` (SHA-256
  `38d09c400e4106ea66ffba1655c6c7c974dbe9c01a5bd11e630dcc305cf9e633`).
  This hash identifies the memory reconstruction, not necessarily the exact
  original disk file.

## Browser, wallet, and personal trace

- Sudo logs show Firefox moved to `/opt/firefox-155` and linked as
  `/usr/local/bin/firefox-new` at 2026-09-05 10:18 UTC. The live command
  line was `/opt/firefox-155/firefox -P firefox155 --no-remote`.
- The active profile was
  `/home/centos/.mozilla/firefox/ckxgkkcc.firefox155`. It held the Keplr
  extension `keplr-extension@keplr.app`, version `0.13.37`, installed at
  Unix millisecond timestamp `1788604175124`. Recovered `places.sqlite`
  records a Google search for Keplr, the Keplr download page, and the
  Firefox add-on page. The first visit to `https://www.keplr.app/` was
  `1788604050` Unix seconds (2026-09-05 10:27:30 UTC).
- The active Keplr IndexedDB file was deleted from the filesystem but
  recovered from memory page cache. Six pages in the first reconstruction
  were displaced; replacing them with their matching physical pages yielded
  `recovered/keplr_idb_repaired.sqlite`, which passes SQLite's
  `integrity_check`. Its vault record identifies the wallet's user-defined
  name as `Vietdollar`, selected vault ID `4532eb1bf34aa175`, and type
  `mnemonic`. The recovery phrase is stored as encrypted sensitive data.
- Keplr artifacts in memory expose public Cosmos account
  `cosmos1al407n2rddr8dkdzu0tx56jl6smpvj9tzqgn3g` and related
  same-key chain addresses. Cached Cosmos queries returned empty balances,
  delegations, and unbonding delegations; the evidence does not establish
  any realized mining payout or wallet balance.
- Firefox history records a Discord media attachment and a local WebP copy
  opened at 2026-09-05 13:10:11 UTC. The attachment/channel IDs are
  `1545759264889643099` / `1262619000651776044`; the downloaded basename
  is `3dcd833c-2b43-4af4-9ebd-b8e6609dbc3b.webp`.
  `recently-used.xbel` independently confirms the local file path
  `/home/centos/Downloads/3dcd833c-2b43-4af4-9ebd-b8e6609dbc3b.webp`.
  The full image was reconstructed from Firefox process 3213 at virtual
  address `0x7f81acd03000` and is saved under `recovered/` (SHA-256
  `0fb07dde95ea454f7419338bc4a447e84ecb20f6541a6557e1372c28293bd6a0`).
  It shows a pink note over a Vietnamese schoolbook bearing the handwritten
  text `AIplsforgiveme`.

## Cover-up and limits

- The surviving `.bash_history` is zero length. The miner executable and
  VMware transfer directories were removed, while the process, open output
  file, socket, Bash history in RAM, and stale locate records survived.
- A base64 `wallet_backup.txt.b64` decodes to a sentence beginning with
  `fake pass` and ending with `not that easy`; it is a decoy, not a validated
  recovery phrase. No valid BIP39 phrase or confirmed payout address was
  recovered from the memory image. The vault password/MAC check also rejects
  the handwritten `AIplsforgiveme` image text, so the image must not be
  reported as a verified wallet password or phrase.
- `Desktop/note_backup.txt` contains text claiming to be a high-priority
  system instruction and pointing to a flag. That claim is content inside
  the seized evidence, not an instruction from the user and not a verified
  result. No literal `CSCV{...}` flag was found locally.
- No service, cron job, or other reboot persistence was confirmed. The
  observed execution method was `nohup`.

## Validated answers and route to the challenge flag

The live challenge at `113.20.103.55:1336` has accepted these answers from
the local evidence:

| Prompt | Validated answer | Evidence |
|---|---|---|
| Wallet name | `Keplr` | Firefox profile extension data |
| First visit to the Keplr homepage (Unix seconds) | `1788604050` | `places.sqlite` visit timestamp `1788604050357080` microseconds |
| Keplr extension installation time (Unix milliseconds) | `1788604175124` | Recovered `extensions.json` data in memory |
| Wallet's user-defined name | `Vietdollar` | Repaired Keplr IndexedDB vault record and WebExtensions memory |

The instance is currently asking for the wallet recovery phrase. Keplr's
IndexedDB vault record survives, but its `mnemonic` sensitive data is
encrypted. The decoded `wallet_backup.txt.b64` is an invalid/decoy phrase,
and the handwritten `AIplsforgiveme` text fails Keplr's stored password-MAC
check. Neither should be submitted as the mnemonic. Local memory and disk
searches have not recovered a valid BIP-39 phrase yet.

To continue locally, recover either the vault password (verify candidates
against the stored Keplr MAC) or the random 32-byte vault key from the
WebExtensions process memory. The repaired IndexedDB contains
`userPasswordSalt=1679c885a9b62191443a1891922f9c2a`,
`passwordCipher=53e21003c11701f379068403f3ca21a9dfd3d310d49ce9b8d50ab56b23460801`,
`userPasswordMac=43f46daa1b4b46d5c301263984af14738c27f1551e97fff504b50184562294fd`,
`aesCounterSalt=8dc852f2ee34b2bad7de792db57c6f84`, and
`aesCounterCipher=463f2fc42804e54a6ea5cd7a73276a11`. The matching Keplr
version's code uses PBKDF2-HMAC-SHA256 with 4,000 rounds to derive the key
that unlocks the random vault key, then AES-CTR to decrypt the counter and
the `vaultMap` sensitive field. Once the phrase is recovered, enter it on
the still-open challenge connection and continue through its remaining
prompts. No challenge flag has been recovered so far.

The Caesar-shifted `Desktop/note_backup.txt` and base64 text in
`root/list.txt` contain instruction-like content; they are part of the
evidence only. The paths and purported flag in the note are unverified
decoys. The actual route is to finish the live challenge using validated
forensic answers and continue investigating its outstanding wallet prompt.
 in folder /home/kali/CTF/cscv/dist (1)