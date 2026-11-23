# Cómo instalar leakguard en Windows

(English below.)

> **Versión preliminar.** leakguard para Windows es nuevo. Su cortafuegos se
> prueba automáticamente en cada cambio con filtros reales de la Plataforma
> de filtrado de Windows (Windows Filtering Platform), pero el ícono de la
> bandeja, el instalador en una PC real y una caída real de la VPN todavía
> no se han probado en una PC con Windows de verdad. Si algo no funciona,
> cuéntanos en https://github.com/Isaacpaezz/leakguard/issues (puedes
> escribir en español).

Necesitas Windows 10 u 11 de 64 bits y una cuenta de administrador (o la
contraseña de una).

## 1. Descarga

1. Entra a la página de versiones:
   https://github.com/Isaacpaezz/leakguard/releases
2. Descarga el instalador de tu PC, de la versión más nueva:
   - `leakguard-VERSIÓN-windows-amd64-setup.exe`: la mayoría de las PC de
     escritorio y laptops (procesador Intel o AMD).
   - `leakguard-VERSIÓN-windows-arm64-setup.exe`: PC con procesador ARM,
     como las que traen Snapdragon.

   ¿No sabes cuál? Abre **Configuración > Sistema > Acerca de** y mira
   **Tipo de sistema**: "procesador basado en x64" es `amd64`; "procesador
   basado en ARM" es `arm64`.
3. Si tu navegador avisa que el archivo no se descarga con frecuencia,
   elige conservarlo (en Edge: **…** > **Conservar** > **Mostrar más** >
   **Conservar de todos modos**).
4. Opcional: para comprobar que el archivo llegó completo, descarga también
   el archivo `.sha256` del mismo nombre. En PowerShell, dentro de la carpeta
   Descargas, ejecuta
   `Get-FileHash .\leakguard-VERSIÓN-windows-amd64-setup.exe` y compara el
   resultado con el texto del archivo `.sha256` (mayúsculas y minúsculas no
   importan).

## 2. Instala

1. Abre el instalador que descargaste.
2. leakguard todavía no está firmado con un certificado, así que Windows
   muestra **"Windows protegió tu PC"**. Haz clic en **Más información** y
   luego en **Ejecutar de todas formas**.
3. Windows pregunta **"¿Quieres permitir que esta aplicación haga cambios en
   el dispositivo?"** (el editor aparece como desconocido). Haz clic en
   **Sí**.
4. Sigue el instalador. Instala leakguard siempre en
   `C:\Program Files\leakguard` (la carpeta no se puede cambiar: solo los
   administradores pueden modificarla) y lo agrega al menú Inicio.

## 3. Configura en 3 pasos

Abre **leakguard** desde el menú Inicio. Aparece un escudo en el área de
notificación (abajo a la derecha, junto al reloj) y una guía en 3 pasos:

1. Elige qué quieres proteger. Windows pregunta servicio por servicio:
   responde **Sí** a los que quieras proteger (por ejemplo, Anthropic
   (Claude)).
2. Encuentra tu VPN: desconéctala y haz clic en **Siguiente**; luego
   conéctala y haz clic en **Siguiente**. leakguard te muestra el nombre del
   adaptador de red que crea tu VPN: con WireGuard suele ser el nombre de tu
   túnel (por ejemplo "VPN (WireGuard Tunnel)"); con la VPN integrada de
   Windows, el nombre que le diste a la conexión (por ejemplo
   "VPN (Conexión VPN)"); con OpenVPN puede ser un nombre como
   "OpenVPN TAP-Windows6" u "OpenVPN Wintun". Ethernet, Wi-Fi y los
   adaptadores de máquinas virtuales nunca se aceptan como VPN.
3. Activa la protección. Windows te pide permiso de administrador una sola
   vez, para instalar el servicio que bloquea esos servicios si tu VPN se
   cae.

Listo. El escudo verde significa que estás protegido. Las ventanas salen en
español si Windows está en español.

leakguard se abre sola cada vez que inicias sesión en Windows. Si no lo
quieres, quita la marca de **Abrir al iniciar sesión** en el menú del
escudo. **Salir** cierra solo el menú: la protección sigue activa.

### Para ver siempre el escudo

Windows suele esconder los íconos nuevos detrás de la flecha **^** junto al
reloj. Para dejar el escudo siempre a la vista:

- **Windows 11:** abre **Configuración > Personalización > Barra de tareas >
  Otros iconos de la bandeja del sistema** y activa **leakguard**.
- **Windows 10:** abre **Configuración > Personalización > Barra de tareas >
  Seleccionar los iconos que aparecerán en la barra de tareas** y activa
  **leakguard**.

También puedes arrastrar el escudo desde la flecha **^** hasta la barra de
tareas.

### Pausar

En el menú del escudo, **Pausar la protección** deja que los servicios usen
tu conexión normal hasta que elijas **Reanudar la protección**. Pausar y
marcar o desmarcar servicios no muestran el aviso de permiso de Windows,
pero necesitan una cuenta de administrador: con una cuenta estándar,
leakguard responde que solo un administrador puede cambiarlo.

## Desde la terminal

Si prefieres no usar el escudo, abre una terminal de administrador: haz clic
derecho en el botón Inicio y elige **Terminal (Administrador)** (en
Windows 10, **Windows PowerShell (Administrador)**). Luego:

```powershell
cd "$env:ProgramFiles\leakguard"
.\leakguard interfaces                                   # busca el nombre de tu VPN (conéctala primero)
.\leakguard enable --vpn "WireGuard Tunnel" anthropic   # protege Claude a través de esa VPN
.\leakguard status                                       # qué está protegido
.\leakguard test                                         # comprueba que Claude se bloquea fuera de la VPN
.\leakguard disable                                      # quita la protección
```

Cambia `WireGuard Tunnel` por el nombre de tu VPN, entre comillas si tiene
espacios. `.\leakguard services` lista lo que puedes proteger. `status` y
`test` también funcionan en una terminal normal.

## Límites

- Windows todavía no cuenta los **bloqueos**: el menú muestra cuánto tiempo
  lleva conectada tu VPN y cuántas veces se cayó hoy, pero no cuántas veces
  leakguard bloqueó un servicio. La protección funciona igual.
- **WSL2** (en su modo normal, NAT), las **máquinas virtuales de Hyper-V**,
  los **contenedores de Hyper-V** y **Docker Desktop** (sus contenedores
  Linux corren dentro de WSL2 y, en Windows 10 y 11, sus contenedores
  Windows usan Hyper-V) todavía no pasan por leakguard: si la
  VPN se cae, un programa dentro de ellos puede llegar a los servicios
  protegidos por tu conexión normal. Para estar protegido, usa Claude Code
  y herramientas parecidas directamente en Windows, no dentro de WSL2 ni de
  una máquina virtual.
- Los contenedores de Windows con aislamiento de procesos (lo normal de
  Docker en Windows Server) no pueden llegar a los servicios protegidos, ni
  siquiera con la VPN conectada.
- Algunos programas de VPN nombran su adaptador de otra forma que los
  ejemplos de arriba. Si leakguard no encuentra tu VPN al conectarla, usa
  **Elegir de una lista** y elige el adaptador de tu VPN.

## Actualizar

Cierra el menú del escudo (**Salir**; la protección sigue activa), descarga
el instalador nuevo y ábrelo igual que la primera vez. Si la protección está
activa, el instalador reinicia el servicio de fondo con la versión nueva y
conserva lo que elegiste. Después abre leakguard desde el menú Inicio.

El registro del servicio está en `C:\ProgramData\leakguard\leakguard.log`.

## Desinstalar

1. Abre **Configuración > Aplicaciones > Aplicaciones instaladas** (en
   Windows 10, **Configuración > Aplicaciones > Aplicaciones y
   características**).
2. Busca **leakguard**, haz clic en **…** (o en la app) y elige
   **Desinstalar**. Windows te pide permiso de administrador.
3. El desinstalador quita la protección (las reglas y el servicio de fondo),
   el programa, el acceso del menú Inicio y la apertura al iniciar sesión.
   Los servicios que protegías vuelven a usar tu conexión normal.

Si el desinstalador no logra quitar la protección por completo, te avisa
y el programa se queda para que puedas intentarlo otra vez: vuelve a
desinstalar desde Configuración, o abre una terminal como administrador y
ejecuta `& "$env:ProgramFiles\leakguard\leakguard.exe" disable`. Los
servicios protegidos pueden seguir bloqueados hasta que termine.

También puedes elegir primero **Desinstalar leakguard…** en el menú del
escudo: quita la protección, el servicio de fondo y la apertura al iniciar
sesión; después quita el programa desde Configuración como arriba.

Para borrar también lo que elegiste, las estadísticas y el registro, borra
la carpeta `C:\ProgramData\leakguard` (Windows te pide permiso de
administrador).

---

# How to install leakguard on Windows

> **Pre-release.** leakguard for Windows is new. Its firewall is tested
> automatically on every change with real Windows Filtering Platform
> filters, but the tray icon, the installer on a real PC and a real VPN drop
> have not yet been tried on a real Windows PC. If something does not work,
> tell us at https://github.com/Isaacpaezz/leakguard/issues.

You need 64-bit Windows 10 or 11 and an administrator account (or the
password of one).

## 1. Download

1. Go to the releases page:
   https://github.com/Isaacpaezz/leakguard/releases
2. Download the installer for your PC from the newest release:
   - `leakguard-VERSION-windows-amd64-setup.exe`: most desktops and laptops
     (Intel or AMD processor).
   - `leakguard-VERSION-windows-arm64-setup.exe`: PCs with an ARM
     processor, such as those with Snapdragon.

   Not sure? Open **Settings > System > About** and look at **System
   type**: "x64-based processor" is `amd64`; "ARM-based processor" is
   `arm64`.
3. If your browser warns that the file is not commonly downloaded, choose to
   keep it (in Edge: **…** > **Keep** > **Show more** > **Keep anyway**).
4. Optional: to check that the file arrived complete, also download the
   `.sha256` file of the same name. In PowerShell, in your Downloads folder,
   run `Get-FileHash .\leakguard-VERSION-windows-amd64-setup.exe` and
   compare the result with the text of the `.sha256` file (upper or lower
   case does not matter).

## 2. Install

1. Open the installer you downloaded.
2. leakguard is not signed with a certificate yet, so Windows shows
   **"Windows protected your PC"**. Click **More info**, then **Run
   anyway**.
3. Windows asks **"Do you want to allow this app to make changes to your
   device?"** (the publisher shows as unknown). Click **Yes**.
4. Follow the installer. It always installs leakguard in
   `C:\Program Files\leakguard` (the folder cannot be changed: only
   administrators may modify it) and adds it to the Start menu.

## 3. Set it up in 3 steps

Open **leakguard** from the Start menu. A shield appears in the notification
area (bottom right, next to the clock), with a 3-step guide:

1. Choose what to protect. Windows asks one service at a time: answer
   **Yes** for the ones to protect (for example, Anthropic (Claude)).
2. Find your VPN: disconnect it and click **Next**; then connect it and
   click **Next**. leakguard shows the name of the network adapter your VPN
   creates: with WireGuard it is usually your tunnel's name (for example
   "VPN (WireGuard Tunnel)"); with the VPN built into Windows, the name you
   gave the connection (for example "VPN (Conexión VPN)"); with OpenVPN it
   may be a name such as "OpenVPN TAP-Windows6" or "OpenVPN Wintun".
   Ethernet, Wi-Fi and virtual machine adapters are never accepted as the
   VPN.
3. Turn the protection on. Windows asks for administrator permission once,
   to install the background service that blocks those services if your VPN
   drops.

Done. A green shield means you are protected. The windows are in Spanish
when Windows is in Spanish.

leakguard opens by itself every time you sign in to Windows. If you do not
want that, untick **Open at login** in the shield menu. **Quit** closes only
the menu: the protection keeps running.

### To always see the shield

Windows usually hides new icons behind the **^** arrow next to the clock. To
keep the shield in view:

- **Windows 11:** open **Settings > Personalization > Taskbar > Other system
  tray icons** and turn **leakguard** on.
- **Windows 10:** open **Settings > Personalization > Taskbar > Select which
  icons appear on the taskbar** and turn **leakguard** on.

You can also drag the shield from the **^** arrow to the taskbar.

### Pause

In the shield menu, **Pause protection** lets the services use your normal
connection until you choose **Resume protection**. Pausing and ticking or
unticking services show no Windows permission prompt, but they need an
administrator account: with a standard account, leakguard answers that
only administrators can change it.

## From the terminal

If you prefer not to use the shield, open an administrator terminal:
right-click the Start button and choose **Terminal (Admin)** (on Windows
10, **Windows PowerShell (Admin)**). Then:

```powershell
cd "$env:ProgramFiles\leakguard"
.\leakguard interfaces                                   # find your VPN's name (connect it first)
.\leakguard enable --vpn "WireGuard Tunnel" anthropic   # protect Claude through that VPN
.\leakguard status                                       # what is protected
.\leakguard test                                         # prove Claude is refused outside the VPN
.\leakguard disable                                      # turn the protection off
```

Replace `WireGuard Tunnel` with your VPN's name, in quotes if it has spaces.
`.\leakguard services` lists what you can protect. `status` and `test` also
work in a normal terminal.

## Limits

- Windows does not count **blocks** yet: the menu shows how long your VPN
  has been connected and how many times it dropped today, but not how many
  times leakguard blocked a service. The protection works the same.
- **WSL2** (in its default NAT mode), **Hyper-V virtual machines**,
  **Hyper-V containers** and **Docker Desktop** (its Linux containers run
  inside WSL2 and, on Windows 10 and 11, its Windows containers use
  Hyper-V) do not go through leakguard yet: if the VPN
  drops, a program inside them can reach the protected services over your
  real connection. To be protected, run Claude Code and similar tools
  directly on Windows, not inside WSL2 or a virtual machine.
- Windows containers with process isolation (Docker's default on Windows
  Server) cannot reach the protected services, even when the VPN is up.
- Some VPN programs name their adapter differently than the examples
  above. If leakguard does not find your VPN when you connect it, use
  **Choose from a list** and pick your VPN's adapter.

## Update

Close the shield menu (**Quit**; the protection keeps running), download the
new installer and open it the same way as the first time. If the protection
is on, the installer restarts the background service with the new version
and keeps your choices. Then open leakguard from the Start menu.

The service's log is `C:\ProgramData\leakguard\leakguard.log`.

## Uninstall

1. Open **Settings > Apps > Installed apps** (on Windows 10, **Settings >
   Apps > Apps & features**).
2. Find **leakguard**, click **…** (or the app) and choose **Uninstall**.
   Windows asks for administrator permission.
3. The uninstaller removes the protection (the rules and the background
   service), the program, the Start menu entry and the login item. The
   services you protected use your normal connection again.

If the uninstaller cannot remove the protection completely, it tells you
and the program stays so you can try again: uninstall again from Settings,
or open a terminal as administrator and run
`& "$env:ProgramFiles\leakguard\leakguard.exe" disable`. The protected
services may stay blocked until it finishes.

You can also first choose **Uninstall leakguard…** in the shield menu: it
removes the protection, the background service and the login item; then
remove the program from Settings as above.

To also delete your choices, the stats and the log, delete the folder
`C:\ProgramData\leakguard` (Windows asks for administrator permission).
