# QseeKeymaster

Elixir client for the Keymaster trusted application in Qualcomm's QSEE
TrustZone, as the bootloader leaves it resident on devices like the
Fairphone 3 (Snapdragon 632). Keymaster is the only hardware-bound key
store such a phone has: there is no secure element, and key material never
leaves TrustZone.

For the full narrative of the work — what was built, what is verified, the
kernel gap that still blocks key operations, and how to close it — see
[REPORT.md](REPORT.md).

## Status

| | |
|---|---|
| Kernel shim (`/dev/qseecom_raw`) | **working** |
| Reaching the application, resolving its ID | **working** |
| Utility commands (`version`, `date_support`) on the phone | **working** |
| The Elixir client (framing, tags, params, messages, calls) | **complete, 27 unit tests** |
| Key operations on the phone (generate, begin/update/finish, …) | **blocked** — kernel has no QSEE listener support |

The whole client is implemented: tags, the parameter-set codec, every
key-operation message and the high-level calls, all unit tested. The
transport and the bootloader-facing utility commands are verified against
a Fairphone 3 running Nerves (HAL 4.0, trusted application 4.164). The key
operations themselves do not yet complete on that phone: the kernel is
missing QSEE listener support (see [Kernel side](#kernel-side)).

## The hardware

The FP3's SoC (Snapdragon 632) has **no StrongBox secure element**. Its
hardware-backed key store is the **Keymaster 4** trusted application
running in **QSEE**, the TrustZone secure world. The stock LK bootloader
loads it from the `keymaster` partition and leaves it resident, so a
booted Linux can reach it over SCM calls.

What that trusted application offers — the crypto surface this client
targets:

- **Hardware-bound keys.** Keys are generated or imported *inside*
  TrustZone and handed back only as opaque, hardware-wrapped key blobs.
  The plaintext key material never crosses into the non-secure OS, so a
  compromised Linux side cannot exfiltrate it — it can only ask the
  trusted application to use a key.
- **Algorithms:** AES (ECB/CBC/CTR/GCM), HMAC, RSA (sign/verify,
  encrypt/decrypt, with the usual paddings) and EC (ECDSA on the NIST
  curves).
- **Purposes** bound into each key at creation: encrypt, decrypt, sign,
  verify, derive-key, wrap-key.
- **Authorizations enforced in hardware:** key size, algorithm, block
  mode, padding, `no_auth_required`, origin and the rest of the AOSP tag
  set — the trusted application refuses to use a key outside the terms it
  was created under.

This client exposes that surface from Elixir. The utility side (version,
date support) is confirmed on the phone today; the key-operation side is
implemented and unit tested but waits on the kernel change below before it
can run against the hardware.

## Pieces

| Module | What |
|---|---|
| `QseeKeymaster` | `version/1`, `date_support/1`, and the key operations: `generate_key/2`, `import_key/4`, `export_key/4`, `get_key_characteristics/3`, `begin/4`, `update/4`, `finish/5`, `abort/2` |
| `QseeKeymaster.Command` | Command IDs from LK's `km_main.h` |
| `QseeKeymaster.Tag` | Keymaster tags, value types and enumerations (AOSP `keymaster_defs.h`) |
| `QseeKeymaster.ParamSet` | AOSP `AuthorizationSet` wire format, encode and decode |
| `QseeKeymaster.Message` | AOSP `android_keymaster_messages.cpp` request and response bodies |
| `QseeKeymaster.Transport` | Behaviour; `Transport.Device` talks to `/dev/qseecom_raw` |

## Kernel side

`/dev/qseecom_raw` comes from the `tee-qseecom` branch of
`nerves_system_fp3`: a patch that adds `fairphone,fp3` to the mainline
qseecom allowlist and a small character device over
`qcom_scm_qseecom_app_send()`.

Mainline qseecom has no listener support. `qcom_scm_qseecom_call()` only
warns on `QSEECOM_RESULT_INCOMPLETE` and `QSEECOM_RESULT_BLOCKED_ON_LISTENER`
and carries on, so any command that makes the application call back to the
non-secure side cannot finish. The self-contained utility commands
(`get_version`, `get_date_support`) return in one call and work; the key
operations block on a listener (secure storage, a monotonic clock) and
fail — `generate_key` even wedges the application until the phone reboots.
Making them work needs the kernel to register listener buffers and loop on
the blocked result, issuing the continue-blocked and listener-response SCM
calls, the way the downstream qseecom driver does. That is a kernel change
plus a reflash.

## Example

```elixir
iex> QseeKeymaster.Transport.Device.lookup()
{:ok, 65537}
iex> QseeKeymaster.version()
{:ok, %{major: 4, minor: 0, ta_major: 4, ta_minor: 164}}
iex> QseeKeymaster.ParamSet.encode([{:algorithm, :aes}, {:key_size, 256}, {:no_auth_required, true}])

# Once the kernel services listeners, the crypto surface is:
iex> {:ok, key} = QseeKeymaster.generate_key([
...>   {:algorithm, :aes}, {:key_size, 256},
...>   {:purpose, :encrypt}, {:purpose, :decrypt},
...>   {:block_mode, :ecb}, {:padding, :none}, {:no_auth_required, true}
...> ])
iex> {:ok, %{op_handle: h}} = QseeKeymaster.begin(:encrypt, key.key_blob, [{:block_mode, :ecb}, {:padding, :none}])
iex> {:ok, %{output: ct}} = QseeKeymaster.finish(h, "sixteen byte msg")
```

## Sources

- LK bootloader `include/km_main.h` (Apache 2.0): command IDs and utility structs.
- AOSP `hardware/libhardware/include/hardware/keymaster_defs.h`,
  `system/keymaster/android_keymaster/authorization_set.cpp` and
  `android_keymaster_messages.cpp` (Apache 2.0): tags, the parameter-set
  serialization and the key-operation message bodies.
- Qualcomm's `KeymasterUtils.h` / `KeymasterBuffer.h` interface headers
  (public): confirm the request is the command ID followed by the AOSP
  message body, built in a direct-plus-indirect buffer.
