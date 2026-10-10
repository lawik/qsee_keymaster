# QseeKeymaster

Elixir client for the Keymaster trusted application in Qualcomm's QSEE
TrustZone, as the bootloader leaves it resident on devices like the
Fairphone 3 (Snapdragon 632). Keymaster is the only hardware-bound key
store such a phone has: there is no secure element, and key material never
leaves TrustZone.

Status: experimental. The transport and the bootloader-facing utility
commands are verified against a Fairphone 3 running Nerves (HAL 4.0,
trusted application 4.164). The key operations (generate, begin, update,
finish, ...) are known by command ID; their request layouts are not public
and are the open work.

## Pieces

| Module | What |
|---|---|
| `QseeKeymaster` | `version/1`, `date_support/1`, `request/2`, `send/4` |
| `QseeKeymaster.Command` | Command IDs from LK's `km_main.h` |
| `QseeKeymaster.Tag` | Keymaster tags, value types and enumerations (AOSP `keymaster_defs.h`) |
| `QseeKeymaster.ParamSet` | AOSP `AuthorizationSet` wire format, encode and decode |
| `QseeKeymaster.Transport` | Behaviour; `Transport.Device` talks to `/dev/qseecom_raw` |

## Kernel side

`/dev/qseecom_raw` comes from the `tee-qseecom` branch of
`nerves_system_fp3`: a patch that adds `fairphone,fp3` to the mainline
qseecom allowlist and a small character device over
`qcom_scm_qseecom_app_send()`. Mainline qseecom can only reach
applications that are already loaded and has no listener support, so a
command that makes the application wait on the non-secure side (RPMB,
time) fails rather than completing.

## Example

```elixir
iex> QseeKeymaster.Transport.Device.lookup()
{:ok, 65537}
iex> QseeKeymaster.version()
{:ok, %{major: 4, minor: 0, ta_major: 4, ta_minor: 164}}
iex> QseeKeymaster.ParamSet.encode([{:algorithm, :aes}, {:key_size, 256}, {:no_auth_required, true}])
```

## Sources

- LK bootloader `include/km_main.h` (Apache 2.0): command IDs and utility structs.
- AOSP `hardware/libhardware/include/hardware/keymaster_defs.h` and
  `system/keymaster/android_keymaster/authorization_set.cpp` (Apache 2.0):
  tags and the parameter-set serialization.
