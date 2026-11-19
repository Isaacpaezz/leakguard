# Feature: step-by-step setup for normal users

Replace the technical first-run menu (interface names like utun4, a password prompt that appears without warning) with a 3-step guided setup in native macOS dialogs, in the Mac's language.
Branch `feat/setup-wizard`; delivered as one PR to `main`.

## Specs

- S1 (L1): "un usuario normal no va a saber que es Utum 1. O sea, un usuario no sabe eso. Entonces eso tiene que ser muy fácil." No interface name (utun4, ipsec0) appears in normal use: not in the wizard, not in the main menu. A technical name may appear only in a tooltip or in the fallback list (S3).
- S2 (L1): "Y que tenga paso 1, paso 2, paso 3, no sé, algo así, que sea muy sencillo, que el usuario sepa lo que va a hacer". A guided setup with three numbered steps, each dialog titled "Paso N de 3" / "Step N of 3", saying what will happen next:
  1. Choose what to protect (supported services by friendly name; planned ones are not offered and get a one-line "coming soon" note).
  2. Find your VPN by disconnecting and reconnecting it (L2 decision): "Desconecta tu VPN y toca Siguiente", then "Ahora conéctala y toca Siguiente"; the VPN is the connected VPN interface that appeared. Exactly one new interface -> found, say "¡Encontramos tu VPN!". None -> explain and offer Retry or Choose from a list. Several -> the list.
  3. Activate protection, with the password warning of S3.
  A last dialog confirms it worked in plain words ("Listo: Claude está protegido. Si tu VPN se cae, Claude deja de conectarse hasta que vuelva.").
- S3 (L1): "porque el usuario no sabe que luego le tiene que poner la contraseña". Before the administrator prompt, step 3 says that the Mac will ask for the password the user uses to unlock the Mac, why (to install the background service that protects them), and that it is asked only this once. The administrator prompt itself uses `with prompt` with a short plain-language reason (closes that item of issue #8).
- S4 (L2 decision): the dialogs and the menu follow the Mac's language: Spanish when the first preferred language starts with `es`, English otherwise. Every user-facing string exists in both languages.
- S5 (L1, simplicity of the menu after setup): the menu shows a plain status ("Protegido" / "Sin protección: tu VPN está desconectada" / "En pausa"), the service checkboxes, "Cambiar de VPN…" (re-runs step 2 and saves through the daemon, no password), Pausar/Reanudar and Salir. No interface submenu.
- S6 (AGENTS.md rule 4, fail closed): cancelling at any step changes nothing; the wizard never sends a partial configuration; detection never guesses between several new interfaces.

## Tasks

| ID | Task | Specs | Route | Commit |
|---|---|---|---|---|
| T1 | Pure wizard flow + i18n catalog + friendly VPN labels in `internal/menubar` (or a new `internal/wizard`), table-tested with a fake dialog driver and fake interface snapshots | S1-S4, S6 | worker | e719b5f |
| T2 | Darwin dialog driver (osascript `display dialog` / `choose from list`, quoted), wire the wizard into the app (auto-open on first launch when not set up; "Configurar leakguard (3 pasos)…" item; "Cambiar de VPN…"), simplified menu, `with prompt` on the admin prompt | S1-S6 | worker | e719b5f, 8f2959c |
| T3 | Docs (README, CHANGELOG, HANDOFF), checks, PR | all | parent | |

## Log

- L1 (owner, 2026-11-17): "Sí, pero debemos ajustarlo, porque un usuario normal no va a saber que es Utum 1. O sea, un usuario no sabe eso. Entonces eso tiene que ser muy fácil. Y que tenga paso 1, paso 2, paso 3, no sé, algo así, que sea muy sencillo, que el usuario sepa lo que va a hacer, porque el usuario no sabe que luego le tiene que poner la contraseña. O sea, esto tiene que ser muy sencillo. Entonces, vamos a corregir eso para que sea muy sencillo para el usuario."
- L2 (owner, 2026-11-18): "continua" after a three-question form that recorded no answer; the parent proceeded with the recommended options: detect the VPN by disconnect/reconnect, native macOS dialogs, language follows the Mac (owner's Mac: `es-US`).
- L3 (evidence): the owner's Mac has two connected VPN interfaces (utun4, ipsec0) and idle system tunnels utun0-3; only ipsec0 is the corporate VPN.
- L4 (parent decision): user-facing Spanish uses neutral "tú" forms, not Rioplatense voseo, because the audience is Venezuela; the example strings in S2 were adjusted accordingly (they were the parent's examples, not the owner's words).
- L5 (worker, T1-T2): wizard in internal/menubar (wizard.go, i18n.go, dialogscript.go); menu simplified; draft checkboxes and the interface submenu removed. When rules are loaded but the VPN is down the status says "Protegido: tu VPN está desconectada y estos servicios no conectan" (shortened in 8f2959c to fit MenuLineLength) (truthful: traffic is blocked), and "Sin protección" only when rules are not verified.
- L6 (verification, escalated item 2): root command quoting held under fuzz through osascript and /bin/sh; no blockers. Should-fix F1 (Spanish status cut at 70 runes) fixed in 8f2959c with a test pinning every status to MenuLineLength.
- L7 (native review, lineage review-4d1e26d234c027e5): approved. Advisories fixed in the next commit: the wizard opened by itself when the daemon restarted (now only on the first poll of a launch, when nothing is installed); wizard errors were silent (now a plain-language dialog and menu line); setup and validation errors reached Spanish dialogs in English (now translated); the "found your VPN" dialog names the friendly label and offers Choose another.
