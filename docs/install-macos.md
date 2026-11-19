# Cómo instalar leakguard en tu Mac

(English below.)

Necesitas macOS 13 Ventura o más nuevo, en una Mac con Apple Silicon o Intel,
y una cuenta de administrador de la Mac.

## 1. Descarga

1. Entra a la página de versiones:
   https://github.com/Isaacpaezz/leakguard/releases
2. Descarga el archivo `leakguard-VERSIÓN-macos.dmg` de la versión más nueva.
3. Opcional: para comprobar que el archivo llegó completo, descarga también
   `leakguard-VERSIÓN-macos.dmg.sha256` y, en la Terminal, dentro de la carpeta
   Descargas, ejecuta `shasum -a 256 -c leakguard-VERSIÓN-macos.dmg.sha256`.
   Debe decir `OK`.

## 2. Instala

1. Abre el archivo `.dmg` (doble clic).
2. Arrastra **leakguard** a la carpeta **Applications** (Aplicaciones) que
   aparece al lado.
3. Expulsa el disco "leakguard" (botón ⏏ en el Finder).

## 3. Ábrela la primera vez

leakguard todavía no está firmada con un certificado de Apple, así que macOS
la bloquea la primera vez y dice que no puede comprobar que esté libre de
software malicioso. Es normal: solo tienes que darle permiso una vez.

**macOS 15 Sequoia o más nuevo:**

1. Abre leakguard desde Aplicaciones. macOS muestra un aviso: toca **Listo**
   (no la muevas a la Papelera).
2. Abre **Configuración del Sistema > Privacidad y seguridad**.
3. Baja hasta "Seguridad". Verás un mensaje sobre leakguard: toca
   **Abrir igualmente**.
4. Escribe tu contraseña de la Mac si te la pide, y toca **Abrir igualmente**
   otra vez.

**macOS 13 Ventura o 14 Sonoma:**

1. En Aplicaciones, haz clic derecho (o Control + clic) sobre leakguard y
   elige **Abrir**.
2. En el aviso, toca **Abrir**.

Después de esto, leakguard abre normalmente.

## 4. Configura en 3 pasos

Al abrirla aparece un escudo en la barra de menú (arriba a la derecha) y una
guía en 3 pasos:

1. Elige qué quieres proteger (por ejemplo, Claude).
2. Encuentra tu VPN: desconéctala y toca Siguiente; luego conéctala y toca
   Siguiente.
3. Activa la protección. Tu Mac te pide tu contraseña una sola vez, para
   instalar el servicio que bloquea esos servicios si tu VPN se cae.

Listo. El escudo lleno significa que estás protegido. No necesitas la
Terminal.

leakguard se abre sola cada vez que entras a tu Mac. Si no lo quieres, quita
la marca de **Abrir al iniciar sesión** en el menú del escudo. La protección
sigue activa aunque cierres el menú.

Si leakguard dice que macOS no deja usar el comando que viene dentro de la
app, vuelve al punto 3 y da el permiso; si sigue pasando, abre un reporte en
https://github.com/Isaacpaezz/leakguard/issues.

## Desinstalar

1. En el menú del escudo, elige **Desinstalar leakguard…** y confirma.
2. Escribe tu contraseña de la Mac. leakguard quita las reglas de protección,
   el servicio de fondo y la apertura al iniciar sesión, y se cierra.
3. Arrastra leakguard desde Aplicaciones a la Papelera.

Si cancelas, no se cambia nada.

---

# How to install leakguard on your Mac

You need macOS 13 Ventura or newer, on an Apple silicon or Intel Mac, and an
administrator account on the Mac.

## 1. Download

1. Go to the releases page:
   https://github.com/Isaacpaezz/leakguard/releases
2. Download `leakguard-VERSION-macos.dmg` from the newest release.
3. Optional: to check that the file arrived complete, also download
   `leakguard-VERSION-macos.dmg.sha256` and, in Terminal, in your Downloads
   folder, run `shasum -a 256 -c leakguard-VERSION-macos.dmg.sha256`. It must
   say `OK`.

## 2. Install

1. Open the `.dmg` file (double-click).
2. Drag **leakguard** onto the **Applications** folder next to it.
3. Eject the "leakguard" disk (the ⏏ button in Finder).

## 3. Open it the first time

leakguard is not signed with an Apple certificate yet, so macOS blocks it the
first time and says it cannot check it for malicious software. That is
expected: you give it permission once.

**macOS 15 Sequoia or newer:**

1. Open leakguard from Applications. macOS shows a warning: click **Done**
   (do not move it to the Trash).
2. Open **System Settings > Privacy & Security**.
3. Scroll down to "Security". You will see a message about leakguard: click
   **Open Anyway**.
4. Enter your Mac password if asked, and click **Open Anyway** again.

**macOS 13 Ventura or 14 Sonoma:**

1. In Applications, right-click (or Control-click) leakguard and choose
   **Open**.
2. In the warning, click **Open**.

After that, leakguard opens normally.

## 4. Set it up in 3 steps

A shield appears in the menu bar (top right), with a 3-step guide:

1. Choose what to protect (for example, Claude).
2. Find your VPN: disconnect it and click Next; then connect it and click
   Next.
3. Turn the protection on. Your Mac asks for your password once, to install
   the background service that blocks those services if your VPN drops.

Done. A filled shield means you are protected. You never need Terminal.

leakguard opens by itself every time you log in. If you do not want that,
untick **Open at login** in the shield menu. The protection keeps running
even if you quit the menu.

If leakguard says macOS does not let it use the command inside the app, go
back to step 3 and give the permission; if it keeps happening, open an issue
at https://github.com/Isaacpaezz/leakguard/issues.

## Uninstall

1. In the shield menu, choose **Uninstall leakguard…** and confirm.
2. Enter your Mac password. leakguard removes the protection rules, the
   background service and the login item, and quits.
3. Drag leakguard from Applications to the Trash.

If you cancel, nothing changes.
