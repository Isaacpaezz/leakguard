# Cómo instalar leakguard en Linux

(English below.)

> **Versión preliminar.** leakguard para Linux es nuevo. Sus reglas de
> cortafuegos se prueban automáticamente con reglas reales de nftables en
> cada cambio, pero el ícono de la bandeja y una caída real de la VPN todavía
> no se han probado en un escritorio Linux de verdad. Si algo no funciona,
> cuéntanos en https://github.com/Isaacpaezz/leakguard/issues (puedes
> escribir en español).

Necesitas una cuenta de administrador (que pueda usar `sudo`). El paquete
`.deb` sirve para Ubuntu, Debian, Linux Mint y otros sistemas basados en
ellos.

## 1. Descarga

1. Entra a la página de versiones:
   https://github.com/Isaacpaezz/leakguard/releases
2. Descarga el `.deb` de tu computadora, de la versión más nueva:
   - `leakguard_VERSIÓN_amd64.deb`: la mayoría de las computadoras de
     escritorio y laptops (procesador Intel o AMD).
   - `leakguard_VERSIÓN_arm64.deb`: computadoras con procesador ARM, como una
     Raspberry Pi 4 o 5 con sistema de 64 bits.

   ¿No sabes cuál? Abre una terminal y ejecuta `dpkg --print-architecture`:
   te dice `amd64` o `arm64`.
3. Opcional: para comprobar que el archivo llegó completo, descarga también
   el archivo `.sha256` del mismo nombre y, en la carpeta Descargas, ejecuta
   `sha256sum -c leakguard_VERSIÓN_amd64.deb.sha256`. Debe decir `OK`.

## 2. Instala

En una terminal, dentro de la carpeta Descargas:

```sh
sudo apt install ./leakguard_VERSIÓN_amd64.deb
```

(Cambia `VERSIÓN` y `amd64` por los de tu archivo.) apt instala también
nftables, que leakguard usa para bloquear, y normalmente zenity, que
muestra sus ventanas.

## 3. Configura en 3 pasos

Abre **leakguard** desde el menú de aplicaciones. Aparece un escudo en la
bandeja del sistema (arriba o abajo a la derecha) y una guía en 3 pasos:

1. Elige qué quieres proteger (por ejemplo, Claude).
2. Encuentra tu VPN: desconéctala y haz clic en Siguiente; luego conéctala
   y haz clic en Siguiente.
3. Activa la protección. Tu computadora te pide tu contraseña de
   administrador una sola vez, para instalar el servicio que bloquea esos
   servicios si tu VPN se cae.

Listo. El escudo lleno significa que estás protegido.

leakguard se abre sola cada vez que inicias sesión. Si no lo quieres, quita
la marca de **Abrir al iniciar sesión** en el menú del escudo. La protección
sigue activa aunque cierres el menú.

### Si no ves el escudo o las ventanas

- **Ubuntu** muestra el escudo sin hacer nada más.
- **Otros escritorios GNOME** (Debian, Fedora y otros) necesitan la extensión
  "AppIndicator and KStatusNotifierItem Support". En Debian instálala con
  `sudo apt install gnome-shell-extension-appindicator`, cierra sesión,
  vuelve a entrar y actívala en la app **Extensiones**.
- **KDE** y **Linux Mint** (Cinnamon) suelen mostrar el escudo en su bandeja.
  Otros escritorios necesitan soporte para "AppIndicator" o
  "StatusNotifierItem".
- Las ventanas de leakguard necesitan **zenity** (en KDE sirve **kdialog**).
  Si leakguard dice "Instala zenity para ver las ventanas de leakguard",
  ejecuta `sudo apt install zenity`.

## Otras distribuciones (.tar.gz)

Si tu sistema no usa `.deb`, descarga `leakguard-VERSIÓN-linux-amd64.tar.gz`
(o `arm64`). Necesitas **nftables** y **systemd**; para el escudo y las
ventanas, también **zenity** (o kdialog) y **pkexec** (polkit). Instala esos
paquetes con el gestor de tu distribución y luego, en la carpeta Descargas:

```sh
tar -xzf leakguard-VERSIÓN-linux-amd64.tar.gz
cd leakguard-VERSIÓN-linux-amd64
sudo install -m 0755 leakguard leakguard-tray /usr/bin/
sudo install -m 0644 leakguard.desktop /usr/share/applications/
sudo install -m 0644 leakguard.png /usr/share/icons/hicolor/256x256/apps/
```

Después abre leakguard desde el menú de aplicaciones y sigue los 3 pasos.

## Desde la terminal

Si prefieres no usar el escudo:

```sh
leakguard interfaces                          # busca el nombre de tu VPN (conéctala primero)
sudo leakguard enable --vpn wg0 anthropic     # protege Claude a través de wg0
leakguard status                              # qué está protegido
leakguard test                                # comprueba que Claude se bloquea fuera de la VPN
sudo leakguard disable                        # quita la protección
```

Cambia `wg0` por el nombre de tu VPN. `leakguard services` lista lo que
puedes proteger.

## Actualizar

Descarga el `.deb` nuevo e instálalo igual que la primera vez
(`sudo apt install ./leakguard_VERSIÓN_amd64.deb`). Si la protección está
activa, el paquete reinicia el servicio de fondo con la versión nueva y
conserva lo que elegiste; las reglas siguen cargadas durante la
actualización, así que nada se escapa. Si no puede actualizarlo, lo dice:
las reglas siguen cargadas y nada se escapa; ejecuta `sudo leakguard enable`
para terminar, o mira qué hace el servicio con `systemctl status leakguard`.

El registro `/var/log/leakguard.log` se rota cada semana y se guardan las
últimas 4 semanas.

## Desinstalar

1. En el menú del escudo, elige **Desinstalar leakguard…** y confirma.
2. Escribe tu contraseña de administrador. leakguard quita las reglas de
   protección, el servicio de fondo y la apertura al iniciar sesión, y se
   cierra.
3. Quita el programa: `sudo apt remove leakguard`.

Si cancelas, no se cambia nada. Si te saltas el paso 1, `sudo apt remove
leakguard` también quita las reglas y el servicio de fondo.

`sudo apt remove` guarda lo que elegiste por si vuelves a instalar
leakguard. Para borrar también eso, las estadísticas y el registro
(`/etc/leakguard`, `/var/lib/leakguard` y `/var/log/leakguard.log`), usa
`sudo apt purge leakguard`.

Con el `.tar.gz`, después de los pasos 1 y 2 borra los archivos que copiaste:
`sudo rm /usr/bin/leakguard /usr/bin/leakguard-tray /usr/share/applications/leakguard.desktop /usr/share/icons/hicolor/256x256/apps/leakguard.png`.

---

# How to install leakguard on Linux

> **Pre-release.** leakguard for Linux is new. Its firewall is tested
> automatically with real nftables rules on every change, but the tray icon
> and a real VPN drop have not yet been tried on a real Linux desktop. If
> something does not work, tell us at
> https://github.com/Isaacpaezz/leakguard/issues.

You need an administrator account (one that can use `sudo`). The `.deb`
package works on Ubuntu, Debian, Linux Mint and systems based on them.

## 1. Download

1. Go to the releases page:
   https://github.com/Isaacpaezz/leakguard/releases
2. Download the `.deb` for your computer from the newest release:
   - `leakguard_VERSION_amd64.deb`: most desktops and laptops (Intel or AMD
     processor).
   - `leakguard_VERSION_arm64.deb`: computers with an ARM processor, such as
     a Raspberry Pi 4 or 5 with a 64-bit system.

   Not sure? Open a terminal and run `dpkg --print-architecture`: it says
   `amd64` or `arm64`.
3. Optional: to check that the file arrived complete, also download the
   `.sha256` file of the same name and, in your Downloads folder, run
   `sha256sum -c leakguard_VERSION_amd64.deb.sha256`. It must say `OK`.

## 2. Install

In a terminal, in your Downloads folder:

```sh
sudo apt install ./leakguard_VERSION_amd64.deb
```

(Use the `VERSION` and `amd64` of your file.) apt also installs nftables,
which leakguard uses to block, and usually zenity, which shows its windows.

## 3. Set it up in 3 steps

Open **leakguard** from the applications menu. A shield appears in the
system tray (top or bottom right), with a 3-step guide:

1. Choose what to protect (for example, Claude).
2. Find your VPN: disconnect it and click Next; then connect it and click
   Next.
3. Turn the protection on. Your computer asks for your administrator
   password once, to install the background service that blocks those
   services if your VPN drops.

Done. A filled shield means you are protected.

leakguard opens by itself every time you log in. If you do not want that,
untick **Open at login** in the shield menu. The protection keeps running
even if you quit the menu.

### If you do not see the shield or the windows

- **Ubuntu** shows the shield with nothing else to do.
- **Other GNOME desktops** (Debian, Fedora and others) need the
  "AppIndicator and KStatusNotifierItem Support" extension. On Debian install
  it with `sudo apt install gnome-shell-extension-appindicator`, log out, log
  back in and turn it on in the **Extensions** app.
- **KDE** and **Linux Mint** (Cinnamon) usually show the shield in their
  tray. Other desktops need "AppIndicator" or "StatusNotifierItem" support.
- leakguard's windows need **zenity** (on KDE, **kdialog** works too). If
  leakguard says "Install zenity to see leakguard's windows", run
  `sudo apt install zenity`.

## Other distributions (.tar.gz)

If your system does not use `.deb`, download
`leakguard-VERSION-linux-amd64.tar.gz` (or `arm64`). You need **nftables**
and **systemd**; for the shield and the windows, also **zenity** (or
kdialog) and **pkexec** (polkit). Install them with your distribution's
package manager, then, in your Downloads folder:

```sh
tar -xzf leakguard-VERSION-linux-amd64.tar.gz
cd leakguard-VERSION-linux-amd64
sudo install -m 0755 leakguard leakguard-tray /usr/bin/
sudo install -m 0644 leakguard.desktop /usr/share/applications/
sudo install -m 0644 leakguard.png /usr/share/icons/hicolor/256x256/apps/
```

Then open leakguard from the applications menu and follow the 3 steps.

## From the terminal

If you prefer not to use the shield:

```sh
leakguard interfaces                          # find your VPN's name (connect it first)
sudo leakguard enable --vpn wg0 anthropic     # protect Claude through wg0
leakguard status                              # what is protected
leakguard test                                # prove Claude is refused outside the VPN
sudo leakguard disable                        # turn the protection off
```

Replace `wg0` with your VPN's name. `leakguard services` lists what you can
protect.

## Update

Download the new `.deb` and install it the same way as the first time
(`sudo apt install ./leakguard_VERSION_amd64.deb`). If the protection is
on, the package restarts the background service with the new version and
keeps your choices; the rules stay loaded during the update, so nothing
leaks. If it cannot update it, it says so: the rules stay loaded and
nothing leaks; run `sudo leakguard enable` to finish, or see what the
service is doing with `systemctl status leakguard`.

The log `/var/log/leakguard.log` is rotated every week, keeping the last 4
weeks.

## Uninstall

1. In the shield menu, choose **Uninstall leakguard…** and confirm.
2. Enter your administrator password. leakguard removes the protection
   rules, the background service and the login item, and quits.
3. Remove the program: `sudo apt remove leakguard`.

If you cancel, nothing changes. If you skip step 1, `sudo apt remove
leakguard` also removes the rules and the background service.

`sudo apt remove` keeps your choices in case you install leakguard again.
To delete them too, with the stats and the log (`/etc/leakguard`,
`/var/lib/leakguard` and `/var/log/leakguard.log`), use
`sudo apt purge leakguard`.

With the `.tar.gz`, after steps 1 and 2 delete the files you copied:
`sudo rm /usr/bin/leakguard /usr/bin/leakguard-tray /usr/share/applications/leakguard.desktop /usr/share/icons/hicolor/256x256/apps/leakguard.png`.
