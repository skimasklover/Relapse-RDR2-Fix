# PS5 RDR2 service-ID whitespace guard

A PS5 homebrew ELF payload that changes a ShellCore service-ID guard to skip entries beginning with an ASCII control character or space. Includes notification toasts, checked tracing syscalls, temporary debugger credentials, and cleanup verification.

## Why this exists

Launching Red Dead Redemption 2 (`CUSA03041`, content ID `UP1004-CUSA03041_00-REDEMPTION000002`) was followed by an uncaught `std::__sce_v2::out_of_range` exception with reason `invalid string position` in ShellCore's `SceAppInstallerJobQueue` thread.

A downloaded app.db passed SQLite integrity checks. However, all seven `SERVICE_ID_ADDCONT_ADD_1` through `_7` values in RDR2's `AppInfoJson` were `"\r\n  "`: carriage return, newline, and two spaces (UTF-8 bytes `0d 0a 20 20`). The separate `ps4serviceIdAddCont1` through `7` columns were SQL NULL. This is evidence of malformed service-ID metadata.

Others have noted that this could be due to the 60fps patch present in certain PS4 games. I've only tested this and noticed a reduction in crashes for RDR2 so far. 

## What changes

At ShellCore-relative offset `0x1527ff0`, the payload changes:

```text
Original: 41 80 3f 00 74 a3 4c 89
Patched:  41 80 3f 20 76 a3 4c 89
```

The initial instructions change from `cmp byte ptr [r15], 0; je skip` to `cmp byte ptr [r15], 0x20; jbe skip`. The branch uses an unsigned comparison. Empty strings, ASCII control-leading strings, and space-leading strings are skipped. It does not trim strings, rewrite the database, or intercept C++ exceptions. IDs beginning with bytes greater than `0x20` continue through the existing code.

## Compatibility and behavior

The offsets and signatures came from the original firmware-12.40-targeted source. The explicit firmware-version gate has been removed; fixed offsets and signatures remain. This does not establish compatibility with other firmware or ShellCore builds.

The payload resolves ShellCore, checks surrounding code signatures, temporarily sets its own debugger authorization/capabilities, attaches, requires a confirmed stopped status, checks thread instruction pointers, verifies current bytes, writes the patch, and reads it back. It attempts rollback if write verification fails. Cleanup attempts to detach and restore the original credentials and verifies credential restoration. These cleanup guarantees apply to normal control flow, not external termination or a console crash.

The change is in RAM and must be reapplied after reboot. Because it modifies ShellCore code, its effect is process-wide rather than limited to RDR2. Do not disable the signature or stopped-process checks.

## Build on macOS

Install the [PS5 Payload SDK](https://github.com/ps5-payload-dev/sdk) following its current documentation, plus its LLVM prerequisites. A typical Homebrew configuration is:

```sh
brew install llvm@18
export LLVM_CONFIG="$(brew --prefix llvm@18)/bin/llvm-config"
export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
make
```

`make restore` builds a separate payload with `RESTORE=1` to restore the original bytes under the same checks.

The included ELF was compiled with Apple Clang targeting `x86_64-sie-ps5` and linked with the locally available Zig LLD, using the SDK CRT, libraries, and linker script. The Makefile describes the standard SDK build route; that route has not been tested on this machine because its external LLVM configuration was unavailable.

## Run and verify

Send `rdr2-service-id-whitespace-fix-debug.elf` to an already running compatible [elfldr](https://github.com/ps5-payload-dev/elfldr). Confirm the final toast contains `RAM patch verified`, credential restoration, and `Service ID guard result: success`. Sending the ELF alone is not confirmation. Then launch RDR2 and check whether the original exception recurs.

`PT_ATTACH: Operation not permitted` means tracing was denied and no patch was written. `target stop not confirmed` also prevents the write. A signature mismatch means the fixed code locations did not match this payload's expected build.

## Validation

See SHA256 hash.

## License and references

Source is GPL-3.0-or-later, preserving the supplied payload's SPDX designation; see LICENSE. Notification layout and SDK APIs follow the PS5 Payload SDK. Temporary tracing credential handling follows the debugger source inspected during development. No authorship of those upstream techniques is claimed.
