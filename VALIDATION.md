PS5 RDR2 service-ID payload validation

PASS: previously compiled with -Wall -Werror; linker completed successfully.
PASS: delivered Downloads ELF matches the workspace build byte for byte.
PASS: ELF is 64-bit x86-64 PIE.
PASS: original and patched arrays extracted from ELF match expected machine code.
PASS: mocked credential setup, normal cleanup, partial setup failure, and failed restoration/retry.
PASS: captured app.db SQLite integrity check.
PASS: all seven captured RDR2 service-ID values are CR LF SPACE SPACE (0d0a2020).

LIMITATIONS:
Unicorn machine-code execution tests could not run: emulator terminated with SIGILL on this Mac, including a minimal smoke test. Alternate version build failed because cmake is unavailable.
A 12-second connection to the PS5 log stream returned zero bytes; no fresh runtime result was observed.
User reported successful payload application. RDR2 launch after application and live patch readback remain independently unverified.

ELF SHA-256: a607725245a7564fff043d8f40b02cffdef45796ffa80604206deeefd737330c
