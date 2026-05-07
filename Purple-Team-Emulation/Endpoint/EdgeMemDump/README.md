# Edge Memory Dump Lab

This folder contains two PowerShell scripts for authorized endpoint security testing and purple-team emulation. They demonstrate how sensitive browser form data can remain in process memory and why endpoint monitoring, credential hygiene, and browser hardening matter.

## Files

- `EdgeMemDump.ps1` finds the main Microsoft Edge (`msedge.exe`) process, opens it with the required process access rights, and writes a minidump to `%TEMP%` using `MiniDumpWriteDump`.
- `EdgeMemCreds.ps1` reads an Edge dump file, defaults to the newest `%TEMP%\edge_*.dmp`, and searches the dump for URL/form-style username and password fields such as `login`, `email`, `username`, `password`, or `pwd`.

## Dump Notes

### Is the password in clear text?

Yes, likely. Microsoft Edge can keep credentials in heap memory in a decrypted state while the browser is active. Although saved browser credentials are encrypted on disk in the `Login Data` database, they may need to be decrypted into RAM so Edge can autofill login fields.

### Where to look in the dump

`EdgeMemDump.ps1` uses dump flag `0x2`, which corresponds to `MiniDumpWithFullMemory`. This means the `.dmp` file contains the process private memory captured at dump time.

The relevant data is not stored as a separate password file inside the dump. It may appear as readable strings in heap memory, mixed into the broader binary contents of the process dump.

## Basic Flow

1. Run `EdgeMemDump.ps1` while Edge is open to create a dump file.
2. Run `EdgeMemCreds.ps1` with the dump path, or with no argument to scan the latest `edge_*.dmp` in `%TEMP%`.
3. Review any matched user/password pairs or standalone password tokens.

Use these scripts only in systems and labs where you have explicit permission. Generated dump files may contain sensitive data and should be protected and deleted when no longer needed.
