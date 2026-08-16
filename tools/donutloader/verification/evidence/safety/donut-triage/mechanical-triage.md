# PoC pre-execution review

- Source: https://github.com/TheWover/donut
- Target: `Donut source tree at reviewed commit`  (141 files)
- Mechanical verdict: **NEEDS-HUMAN-REVIEW** (high: 67, medium: 1)

## Automated findings

| Severity | File:line | Check | Why it matters | Evidence |
|---|---|---|---|---|
| high | `.github/workflows/python-publish.yml:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `docs.github.com` |
| high | `.gitmodules:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `github.com` |
| high | `CHANGELOG.md:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `github.com` |
| high | `DemoCreateProcess/DemoCreateProcess.csproj:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `schemas.microsoft.com` |
| high | `DemoCreateProcess/Properties/AssemblyInfo.cs:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `1.0.0.0` |
| high | `DemoCreateProcess/Readme.md:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `www.mono-project.com` |
| high | `Dockerfile:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `github.com` |
| high | `DonutTest/DonutTest.csproj:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `schemas.microsoft.com` |
| high | `DonutTest/Program.cs:106` | dynamic-eval | executes decoded or decompressed data, hiding its real behaviour from review | `byte[] shellcode = Convert.FromBase64String(s);` |
| high | `DonutTest/Properties/AssemblyInfo.cs:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `1.0.0.0` |
| high | `DonutTest/Readme.md:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `www.mono-project.com` |
| high | `DonutTest/rundotnet.exe:0` | binary-artifact | compiled or binary artefact - source review is impossible here; analyse statically on REMnux (VM 105) before it is ever executed | `entropy 6.40` |
| high | `ModuleMonitor/ModuleMonitor.csproj:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `schemas.microsoft.com` |
| high | `ModuleMonitor/ModuleMonitor.csproj.user:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `schemas.microsoft.com` |
| high | `ModuleMonitor/Program.cs:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `stackoverflow.com` |
| high | `ModuleMonitor/Properties/AssemblyInfo.cs:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `1.0.0.0` |
| high | `ModuleMonitor/README.md:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `github.com` |
| high | `ModuleMonitor/app.manifest:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `1.0.0.0, 6.0.0.0, schemas.microsoft.com` |
| high | `ModuleMonitor/img/detected.png:0` | binary-artifact | compiled or binary artefact - source review is impossible here; analyse statically on REMnux (VM 105) before it is ever executed | `entropy 7.96` |
| high | `ProcessManager/ProcessManager.csproj:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `schemas.microsoft.com` |
| high | `ProcessManager/ProcessManager.csproj.user:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `schemas.microsoft.com` |
| high | `ProcessManager/Program.cs:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `pinvoke.net, stackoverflow.com` |
| high | `ProcessManager/Properties/AssemblyInfo.cs:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `1.0.0.0` |
| high | `ProcessManager/README.md:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `github.com` |
| high | `ProcessManager/img/usage.JPG:0` | binary-artifact | compiled or binary artefact - source review is impossible here; analyse statically on REMnux (VM 105) before it is ever executed | `entropy 7.55` |
| high | `README.md:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `blog.xpnsec.com, bloodhoundgang.herokuapp.com, docs.microsoft.com, gist.github.com, github.com, img.shields.io, modexp.wordpress.com, thewover.github.io, tinycrypt.wordpress.com, twitter.com, www.somsubhra.com` |
| high | `docs/2019-08-21-Python_Extension.md:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `docs.microsoft.com, github.com, ibsensoftware.com, twitter.com, www.staging-server.com` |
| high | `docs/2019-5-31-Apple-Fritter.md:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `en.wikipedia.org, github.com, modexp.wordpress.com` |
| high | `docs/2019-5-9-Introducing-Donut.md:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `docs.microsoft.com, en.wikipedia.org, github.com, www.fireeye.com` |
| high | `docs/devnotes.md:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `blog.gentilkiwi.com, docs.microsoft.com, github.com, ibsensoftware.com, modexp.wordpress.com, mysmartlogon.com, pingcastle.com, tinycrypt.wordpress.com, twitter.com, www.staging-server.com` |
| high | `docs/donut.1:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `modexp.wordpress.com, thewover.github.io` |
| high | `donut.c:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `stackoverflow.com` |
| high | `donutmodule.c:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `docs.python.org` |
| high | `format.c:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `github.com` |
| high | `generators/Readme.md:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `github.com` |
| high | `hash.c:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `stackoverflow.com` |
| high | `img/ST_generate_and_copy.PNG:0` | binary-artifact | compiled or binary artefact - source review is impossible here; analyse statically on REMnux (VM 105) before it is ever executed | `entropy 7.70` |
| high | `img/ST_generate_and_copy_86.PNG:0` | binary-artifact | compiled or binary artefact - source review is impossible here; analyse statically on REMnux (VM 105) before it is ever executed | `entropy 7.64` |
| high | `img/ST_inject.PNG:0` | binary-artifact | compiled or binary artefact - source review is impossible here; analyse statically on REMnux (VM 105) before it is ever executed | `entropy 7.88` |
| high | `img/ST_success.PNG:0` | binary-artifact | compiled or binary artefact - source review is impossible here; analyse statically on REMnux (VM 105) before it is ever executed | `entropy 7.97` |
| high | `img/detected.png:0` | binary-artifact | compiled or binary artefact - source review is impossible here; analyse statically on REMnux (VM 105) before it is ever executed | `entropy 7.97` |
| high | `img/donut.PNG:0` | binary-artifact | compiled or binary artefact - source review is impossible here; analyse statically on REMnux (VM 105) before it is ever executed | `entropy 7.98` |
| high | `img/donut_logo.png:0` | binary-artifact | compiled or binary artefact - source review is impossible here; analyse statically on REMnux (VM 105) before it is ever executed | `entropy 7.98` |
| high | `img/donut_logo_black.jpg:0` | binary-artifact | compiled or binary artefact - source review is impossible here; analyse statically on REMnux (VM 105) before it is ever executed | `entropy 7.77` |
| high | `img/donut_logo_white.jpg:0` | binary-artifact | compiled or binary artefact - source review is impossible here; analyse statically on REMnux (VM 105) before it is ever executed | `entropy 7.76` |
| high | `img/generate_and_copy.PNG:0` | binary-artifact | compiled or binary artefact - source review is impossible here; analyse statically on REMnux (VM 105) before it is ever executed | `entropy 7.70` |
| high | `img/iexplore.png:0` | binary-artifact | compiled or binary artefact - source review is impossible here; analyse statically on REMnux (VM 105) before it is ever executed | `entropy 7.93` |
| high | `include/aplib.h:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `www.ibsensoftware.com` |
| high | `include/depack.h:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `www.ibsensoftware.com` |
| high | `include/donut.h:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `github.com` |
| high | `include/donut.ico:0` | binary-artifact | compiled or binary artefact - source review is impossible here; analyse statically on REMnux (VM 105) before it is ever executed | `entropy 2.84` |
| high | `include/mmap-windows.c:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `msdn.microsoft.com` |
| high | `lib/aplib32.a:0` | binary-artifact | compiled or binary artefact - source review is impossible here; analyse statically on REMnux (VM 105) before it is ever executed | `entropy 5.58` |
| high | `lib/aplib32.lib:0` | binary-artifact | compiled or binary artefact - source review is impossible here; analyse statically on REMnux (VM 105) before it is ever executed | `entropy 6.53` |
| high | `lib/aplib64.a:0` | binary-artifact | compiled or binary artefact - source review is impossible here; analyse statically on REMnux (VM 105) before it is ever executed | `entropy 5.09` |
| high | `lib/aplib64.lib:0` | binary-artifact | compiled or binary artefact - source review is impossible here; analyse statically on REMnux (VM 105) before it is ever executed | `entropy 6.42` |
| high | `loader/bypass.c:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `gist.github.com` |
| high | `loader/clib.c:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `github.com` |
| high | `loader/depack.c:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `www.ibsensoftware.com` |
| high | `loader/encode/encode.exe:0` | binary-artifact | compiled or binary artefact - source review is impossible here; analyse statically on REMnux (VM 105) before it is ever executed | `entropy 6.42` |
| high | `loader/encode/mmap-windows.c:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `msdn.microsoft.com` |
| high | `loader/exe2h/mmap-windows.c:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `msdn.microsoft.com` |
| high | `loader/peb.h:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `blog.rewolf.pl` |
| high | `loader/test/debug.cpp:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `docs.microsoft.com` |
| high | `loader/test/rdt.cpp:139` | dynamic-eval | executes decoded or decompressed data, hiding its real behaviour from review | `// ([system.reflection.assembly]::loadfile("C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll")).FullName` |
| high | `loader/test/rdt.cpp:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `3.0.0.0, 4.0.0.0, docs.microsoft.com` |
| high | `setup.py:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `github.com` |
| medium | `DonutTest/Program.cs:13` | obfuscation | large encoded or escaped blob - review its decoded content before running | `static string x64 = @"6HAaAABwGgAAMt355FGs7iIDer99AHARvjkxLxFrCx+e49pHTB2Y2JygBOYZO93j5g9qMawSYNBH/Skv4IAySQ/IhC9+ERbU0y3UElSCHcYgycykIMbrrIF6t0P018mDnwGJXpgnZz4MI4Cq0KsIiIJDJyZBKo/1asaF0iz6g49ze5z8Se` |

## Disposition

The mechanical screen intentionally does not clear this source. Its findings were
resolved by the complete human review in `poc-reviews/donut/poc-review.md`; the
pre-execution verdict and mandatory restrictions are repeated in the adjacent
`../poc-review.md`.
