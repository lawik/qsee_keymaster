# TrustZone Keymaster interop on the Fairphone 3

A record of the work to perform hardware-bound crypto from Elixir through
Qualcomm's QSEE TrustZone on the Fairphone 3 (Snapdragon 632). It covers
what was built, what is verified against the phone, the one thing that
still blocks real key operations, and how to lift that block.

## Status at a glance

Working:

- [x] Kernel shim exposing `/dev/qseecom_raw`, on the `tee-qseecom` branch
- [x] Reaching the resident Keymaster application and resolving its ID
      (`keymaster64`, app ID `65537`)
- [x] The full Elixir client — framing, tags, parameter sets, every
      message, the high-level calls — with 27 passing unit tests
- [x] `get_version` on the phone → HAL 4.0, TA 4.164
- [x] `get_date_support` on the phone → status 0

Not working yet:

- [ ] Any key operation (`generate_key`, `begin`/`update`/`finish`, …) —
      they block on a QSEE listener the mainline kernel does not service,
      so they never complete, and `generate_key` wedges the application
      until reboot
- [ ] The kernel listener handling that would unblock them (designed, not
      written; needs a rebuild + reflash)

The client is done. The remaining work is entirely kernel-side.

## Goal

The FP3 has no secure element. Its only hardware-bound key store is the
Keymaster 4 trusted application running in QSEE (Qualcomm's TrustZone).
The stock LK bootloader loads it from the `keymaster` partition and leaves
it resident — it sends a milestone command and never shuts it down — so a
booted Linux can reach it if the kernel lets userspace issue SCM calls to
it. The aim: drive that application from Elixir to generate and use keys
whose material never leaves TrustZone (for disk encryption, among other
things).

## Approach, and one that was rejected

The integration is an **Elixir client that speaks the application's wire
protocol directly**, over a thin kernel character device.

An OpenSSL engine was considered and rejected: QSEE Keymaster is not a
PKCS#11 / engine provider, so there is no existing engine to bind to with
a NIF. The application speaks the AOSP Keymaster contract, not PKCS#11.
Wrapping it in an engine would mean first writing the same client and then
hiding it behind an engine shim. The Elixir client *is* the integration.

Every wire layout was derived **from open source** — no reversing of
proprietary binaries was needed (see [Sources](#sources)).

## The three pieces

| Where | What |
|---|---|
| `nerves_system_fp3`, branch `tee-qseecom` | Kernel shim: allowlists the FP3 for mainline qseecom and exposes `/dev/qseecom_raw` |
| `qsee_keymaster` (this repo) | The Elixir Keymaster client: framing, tags, parameter sets, messages, transport |
| `fp3_extras` | Carries the transport module (`Fp3Extras.TEE.QSEECom`) for use from the phone app |

### Kernel shim

`patches/linux/0001-firmware-qcom-qseecom-raw-userspace-device.patch` adds
`fairphone,fp3` to the mainline qseecom allowlist in `qcom_scm.c` and a
small misc character device, `drivers/firmware/qcom/qcom_qseecom_raw.c`,
over `qcom_scm_qseecom_app_send()`. `linux-6.19.defconfig` sets
`CONFIG_QCOM_QSEECOM=y` and `CONFIG_QCOM_QSEECOM_RAW=y`, with
`CONFIG_QCOM_QSEECOM_UEFISECAPP` off.

Committed as one commit (no attribution), rebased onto upstream
`origin/main` at `v0.3.0` (`d828a36`), and pushed to the fork remote
`lawik` as branch `tee-qseecom` for a PR.

### Elixir client

| Module | What |
|---|---|
| `QseeKeymaster` | `version/1`, `date_support/1`, and the key operations: `generate_key/2`, `import_key/4`, `export_key/4`, `get_key_characteristics/3`, `begin/4`, `update/4`, `finish/5`, `abort/2` |
| `QseeKeymaster.Command` | Command IDs from LK's `km_main.h` |
| `QseeKeymaster.Tag` | Keymaster tags, value types, enumerations (AOSP `keymaster_defs.h`) |
| `QseeKeymaster.ParamSet` | AOSP `AuthorizationSet` wire format, encode and decode |
| `QseeKeymaster.Message` | AOSP `android_keymaster_messages.cpp` request and response bodies, at message version 3 |
| `QseeKeymaster.Transport` | Behaviour; `Transport.Device` talks to `/dev/qseecom_raw` |

27 unit tests pass. The client is complete: tags, the parameter-set codec,
every key-operation message, the high-level calls.

## Protocol

**Device, `/dev/qseecom_raw`.** One write carries the application name and
the request; the next read returns the kernel status, the application's
QSEE ID, and the response buffer.

```
write: <<name_len::little-32, rsp_len::little-32>> <> app_name <> request
read:  <<status::little-signed-32, app_id::little-32, rsp::binary>>
```

An empty request is a lookup — it resolves the application's ID without
sending it anything.

**Request framing.** Every request is a 32-bit little-endian command ID
followed by the body:

```
<<cmd_id::little-32>> <> body
```

The command IDs come from LK's `km_main.h` (`generate_key` `0x108`,
`get_key_characteristics` `0x109`, `import` `0x10B`, `export` `0x10C`,
`begin` `0x10F`, `update` `0x111`, `finish` `0x112`, `abort` `0x113`,
`get_version` `0x200`, `get_date_support` `0x215`). The body is the AOSP
`android_keymaster_messages.cpp` serialization at message version 3, which
is what Keymaster 4 negotiates.

## Verified on the phone

Against a Fairphone 3 running Nerves, over SSH (which evaluates Elixir):

- QSEECOM version `0x1001000`.
- The application registers itself as **`keymaster64`** — not `keymaster`,
  which is the partition name. App ID `65537`.
- `get_version` → HAL 4.0, trusted application 4.164, status 0.
- `get_date_support` (`0x215`) → status 0.
- `gatekeeper` and `cmnlib` are not found by lookup.

So the transport, the framing, and the self-contained utility commands are
confirmed end to end.

## The blocker: no QSEE listener support in the kernel

The mainline qseecom SCM path **does not service QSEE listeners.**
`qcom_scm_qseecom_call()` in `drivers/firmware/qcom/qcom_scm.c` only
`WARN_ON`s the two results that mean "the application needs the non-secure
side to do something" — `QSEECOM_RESULT_INCOMPLETE` (1) and
`QSEECOM_RESULT_BLOCKED_ON_LISTENER` (2) — and then carries on. There is
an explicit `TODO` about it (around line 1837).

That line cleanly splits what works from what does not:

- **Utility commands** (`get_version`, `get_date_support`) are
  self-contained. The application answers in one call. They work.
- **Key operations** call back into the OS through a listener — for secure
  storage, for a monotonic clock — and so they block. They cannot finish.

On the phone, `generate_key` (`0x108`) returns a read EOF and, worse,
**wedges the application**: afterward even `get_version` returns stale,
recycled-buffer bytes until the phone is rebooted. A reboot restores it.

This is a kernel-side gap, not a client problem. The client encodes the
right bytes; the SCM path drops the application's request to be called
back.

## How to lift it

Add listener handling to the `tee-qseecom` kernel driver, the way the
downstream qseecom driver does:

1. Register listener buffers with QSEE.
2. When a call returns `BLOCKED_ON_LISTENER`, loop: service the listener
   request, then issue the continue-blocked and listener-response SCM
   calls until the application returns a final result.

Then rebuild the system and reflash. That rebuild/reflash is a step the
device owner runs; the kernel change is the next lever, and it is the only
thing between the finished client and working hardware-bound crypto.

## Sources

All layouts came from public, open-source material. No proprietary binary
was reversed.

- LK bootloader `include/km_main.h` (Apache 2.0): command IDs and the
  utility structs.
- AOSP (Apache 2.0): `keymaster_defs.h` for tags and enums,
  `authorization_set.cpp` for the parameter-set serialization,
  `android_keymaster_messages.cpp` for the key-operation message bodies.
  Reference clone: `LineageOS/android_system_keymaster`, branch
  `lineage-17.1`.
- Qualcomm's public interface headers `KeymasterUtils.h` and
  `KeymasterBuffer.h`: confirm the request is the command ID followed by
  the AOSP message body, assembled in a direct-plus-indirect buffer. The
  confirmation that the TA speaks stock AOSP serialization came from
  Qualcomm's own dump shipping AOSP's `authorization_set.cpp` and
  `serializable.cpp` verbatim.
