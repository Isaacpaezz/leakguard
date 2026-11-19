package menubar

import (
	"fmt"
	"strings"
)

// Lang is the language of every user-facing string: the dialogs and the menu
// follow the Mac's first preferred language.
type Lang string

const (
	Spanish Lang = "es"
	English Lang = "en"
)

// ParseLang returns the language for the output of
// "defaults read -g AppleLanguages" (a list such as ("es-US", "en-US")) or
// for a single language tag: Spanish when the first language is Spanish,
// English otherwise, including when nothing could be read.
func ParseLang(appleLanguages string) Lang {
	fields := strings.FieldsFunc(appleLanguages, func(r rune) bool {
		return strings.ContainsRune("(),\" \t\r\n", r)
	})
	if len(fields) == 0 {
		return English
	}
	tag := strings.ToLower(fields[0])
	if tag == "es" || strings.HasPrefix(tag, "es-") || strings.HasPrefix(tag, "es_") {
		return Spanish
	}
	return English
}

// Msg names one user-facing string.
type Msg int

// The menu's strings, used by cmd/leakguard-menubar.
const (
	MsgMenuSetUp Msg = iota
	MsgMenuSetUpTip
	MsgMenuChangeVPN
	MsgMenuChangeVPNTip
	MsgMenuPause
	MsgMenuResume
	MsgMenuToggleTip
	MsgMenuQuit
	MsgMenuQuitTip
	MsgMenuServicesHeader
	MsgMenuServiceTip
	MsgMenuErrorTip
	MsgCatalogError
	MsgMenuOpenAtLogin
	MsgMenuOpenAtLoginTip
	MsgMenuUninstall
	MsgMenuUninstallTip
	MsgLoginItemFailed

	msgComingSoonItem
	msgStatusChecking
	msgStatusNotSetUp
	msgStatusUpdate
	msgStatusProtected
	msgStatusProtectedOffline
	msgStatusOffline
	msgStatusPaused
	msgStatusNotProtected
	msgTooltip
	msgTooltipVPN
	msgTooltipReason
	msgSessionConnected
	msgSessionDisconnected
	msgToday
	msgNoBlocks
	msgOneBlock
	msgBlocks
	msgOneDrop
	msgDrops
	msgTodayVPN

	msgExplainNotSetUp
	msgExplainNotAuthorized
	msgExplainTimeout
	msgExplainOther
	msgErrComingSoon
	msgErrUnknownService
	msgErrNothingToResume
	msgErrNotSetUp
	msgCLINotRootOwned
	msgCLIUpdate
	msgCLIMissing
	msgErrUnsafeCLIPath
	msgErrInvalidChoice
	msgErrUnexpectedAnswer
	msgErrQuarantined

	msgStepTitle
	msgChangeVPNTitle
	msgAppTitle
	msgButtonCancel
	msgButtonNext
	msgButtonActivate
	msgButtonRetry
	msgButtonList
	msgButtonOK
	msgButtonUseVPN
	msgButtonChooseAnother
	msgStep1
	msgStep1ComingSoon
	msgStep1NoServices
	msgStep2Disconnect
	msgStep2Connect
	msgStep2Found
	msgStep2None
	msgStep2NoneConnected
	msgStep2List
	msgStep3Password
	msgStep3NoPassword
	msgAdminPrompt
	msgDoneOne
	msgDoneMany
	msgDoneShield
	msgChangeVPNDone
	msgActivateFailed
	msgChangeVPNFailed
	msgWizardFailed
	msgAnd
	msgKindVPN
	msgKindIPsec
	msgKindWireGuard
	msgKindPPP
	msgTooltipVersion

	msgUninstallTitle
	msgUninstallConfirm
	msgButtonUninstall
	msgUninstallPrompt
	msgUninstallCancelled
	msgUninstallFailed
	msgUninstallCleanupFailed
	msgUninstallDone

	msgCount
)

type text struct{ es, en string }

// MenuLineLength bounds the status, session, today and error lines of the
// menu, in runes.
const MenuLineLength = 70

// messages holds every string in both languages; a test checks that none is
// missing or empty.
var messages = [msgCount]text{
	MsgMenuSetUp:          {"Configurar leakguard (3 pasos)…", "Set up leakguard (3 steps)…"},
	MsgMenuSetUpTip:       {"Te guía en 3 pasos: qué proteger, tu VPN y activar la protección", "Guides you in 3 steps: what to protect, your VPN, and turning the protection on"},
	MsgMenuChangeVPN:      {"Cambiar de VPN…", "Change VPN…"},
	MsgMenuChangeVPNTip:   {"Vuelve a buscar tu VPN; no pide contraseña", "Finds your VPN again; no password needed"},
	MsgMenuPause:          {"Pausar la protección", "Pause protection"},
	MsgMenuResume:         {"Reanudar la protección", "Resume protection"},
	MsgMenuToggleTip:      {"En pausa, los servicios usan tu conexión normal hasta que reanudes", "While paused, the services use your normal connection until you resume"},
	MsgMenuQuit:           {"Salir", "Quit"},
	MsgMenuQuitTip:        {"Cierra solo este menú; la protección sigue activa", "Closes this menu only; the protection keeps running"},
	MsgMenuServicesHeader: {"Proteger estos servicios:", "Protect these services:"},
	MsgMenuServiceTip:     {"Este servicio solo podrá usar tu VPN", "This service may only use your VPN"},
	MsgMenuErrorTip:       {"El último cambio no funcionó", "The last change did not work"},
	MsgCatalogError:       {"No se pudo leer la lista de servicios: %s", "Could not read the service list: %s"},
	MsgMenuOpenAtLogin:    {"Abrir al iniciar sesión", "Open at login"},
	MsgMenuOpenAtLoginTip: {"Abre este menú cada vez que entras a tu Mac; no pide contraseña", "Opens this menu every time you log in to your Mac; no password needed"},
	MsgMenuUninstall:      {"Desinstalar leakguard…", "Uninstall leakguard…"},
	MsgMenuUninstallTip:   {"Quita la protección, el servicio de fondo y la apertura al iniciar sesión", "Removes the protection, the background service and the login item"},
	MsgLoginItemFailed:    {"No se pudo cambiar la apertura al iniciar sesión: %s", "Could not change the login item: %s"},

	msgComingSoonItem:         {"%s (próximamente)", "%s (coming soon)"},
	msgStatusChecking:         {"Comprobando…", "Checking…"},
	msgStatusNotSetUp:         {"leakguard todavía no está configurado", "leakguard is not set up yet"},
	msgStatusUpdate:           {"Hay que actualizar leakguard: toca Configurar", "leakguard needs an update: click Set up"},
	msgStatusProtected:        {"Protegido", "Protected"},
	msgStatusProtectedOffline: {"Protegido: tu VPN está desconectada y estos servicios no conectan", "Protected: your VPN is disconnected, so these services are offline"},
	msgStatusOffline:          {"Sin protección: tu VPN está desconectada", "Not protected: your VPN is disconnected"},
	msgStatusPaused:           {"En pausa", "Paused"},
	msgStatusNotProtected:     {"Sin protección: leakguard no pudo comprobar sus reglas", "Not protected: leakguard could not verify its rules"},
	msgTooltip:                {"leakguard: %s", "leakguard: %s"},
	msgTooltipVPN:             {"%s · VPN: %s", "%s · VPN: %s"},
	msgTooltipReason:          {"%s · %s", "%s · %s"},
	msgSessionConnected:       {"VPN conectada hace %s", "VPN connected for %s"},
	msgSessionDisconnected:    {"VPN desconectada hace %s", "VPN disconnected for %s"},
	msgToday:                  {"Hoy: %s", "Today: %s"},
	msgNoBlocks:               {"sin bloqueos", "no blocks"},
	msgOneBlock:               {"1 bloqueo", "1 block"},
	msgBlocks:                 {"%d bloqueos", "%d blocks"},
	msgOneDrop:                {"la VPN se cayó 1 vez", "VPN dropped 1 time"},
	msgDrops:                  {"la VPN se cayó %d veces", "VPN dropped %d times"},
	msgTodayVPN:               {"Hoy: %s por la VPN", "Today: %s on the VPN"},

	msgExplainNotSetUp:      {"leakguard no está configurado en esta Mac", "leakguard is not set up on this Mac"},
	msgExplainNotAuthorized: {"Solo un administrador de la Mac puede cambiar leakguard", "Only administrators can change leakguard"},
	msgExplainTimeout:       {"El servicio de leakguard no respondió; inténtalo de nuevo", "The leakguard background service did not answer; try again"},
	msgExplainOther:         {"No se pudo cambiar leakguard: %s", "Could not change leakguard: %s"},
	msgErrComingSoon:        {"%s llegará pronto y todavía no se puede proteger", "%s is coming soon and cannot be protected yet"},
	msgErrUnknownService:    {"Servicio desconocido: %q", "Unknown service %q"},
	msgErrNothingToResume:   {"No hay nada que reanudar: configura leakguard primero", "Nothing to resume: set up leakguard first"},
	msgErrNotSetUp:          {"Configura leakguard primero", "Set up leakguard first"},
	msgCLINotRootOwned:      {"El leakguard instalado no pertenece a root. Reinstálalo con: sudo leakguard enable", "The installed leakguard is not owned by root. Reinstall it with: sudo leakguard enable"},
	msgCLIUpdate:            {"Para actualizar leakguard, pon el nuevo comando leakguard junto a esta app o ejecuta: sudo leakguard enable", "To update leakguard, put the new leakguard command next to this app, or run: sudo leakguard enable"},
	msgCLIMissing:           {"Pon el comando leakguard junto a esta app e inténtalo de nuevo", "Put the leakguard command next to this app, then try again"},
	msgErrUnsafeCLIPath:     {"No se puede usar el comando leakguard que está junto a esta app: su ubicación no es válida", "The leakguard command next to this app cannot be used: its location is not valid"},
	msgErrInvalidChoice:     {"La VPN o los servicios elegidos no son válidos; vuelve a configurar leakguard", "The chosen VPN or services are not valid; set up leakguard again"},
	msgErrUnexpectedAnswer:  {"La ventana respondió algo inesperado", "The dialog gave an unexpected answer"},
	msgErrQuarantined:       {"macOS no deja usar el comando leakguard que viene dentro de la app. Sigue la guía «Cómo abrir leakguard» del disco de instalación o https://github.com/Isaacpaezz/leakguard/blob/main/docs/install-macos.md", "macOS does not let the app use the leakguard command inside it. Follow the guide «Cómo abrir leakguard» on the install disk or https://github.com/Isaacpaezz/leakguard/blob/main/docs/install-macos.md"},
	msgStepTitle:            {"Paso %d de 3", "Step %d of 3"},
	msgChangeVPNTitle:       {"Cambiar de VPN", "Change VPN"},
	msgAppTitle:             {"leakguard", "leakguard"},
	msgButtonCancel:         {"Cancelar", "Cancel"},
	msgButtonNext:           {"Siguiente", "Next"},
	msgButtonActivate:       {"Activar", "Activate"},
	msgButtonRetry:          {"Reintentar", "Retry"},
	msgButtonList:           {"Elegir de una lista", "Choose from a list"},
	msgButtonOK:             {"Aceptar", "OK"},
	msgButtonUseVPN:         {"Usar esta VPN", "Use this VPN"},
	msgButtonChooseAnother:  {"Elegir otra", "Choose another"},
	msgStep1:                {"Elige qué quieres proteger.\n\nEstos servicios solo podrán usar tu VPN: si tu VPN se cae, dejan de conectarse hasta que vuelva.", "Choose what to protect.\n\nThese services may only use your VPN: if your VPN drops, they stop connecting until it is back."},
	msgStep1ComingSoon:      {"Próximamente: %s.", "Coming soon: %s."},
	msgStep1NoServices:      {"Todavía no hay servicios que se puedan proteger.", "There are no services that can be protected yet."},
	msgStep2Disconnect:      {"Ahora vamos a encontrar tu VPN.\n\nDesconecta tu VPN y toca Siguiente.", "Now let's find your VPN.\n\nDisconnect your VPN, then click Next."},
	msgStep2Connect:         {"Ahora conéctala y toca Siguiente.", "Now connect it again, then click Next."},
	msgStep2Found:           {"¡Encontramos tu VPN!\n\nLa que conectaste aparece como: %s.\n\nSi no es la tuya, toca Elegir otra.", "We found your VPN!\n\nThe one you connected shows up as: %s.\n\nIf it is not yours, click Choose another."},
	msgStep2None:            {"No vimos aparecer una VPN nueva.\n\nDesconecta tu VPN cuando te lo pidamos y conéctala en el paso siguiente; luego toca Reintentar. También puedes elegirla de una lista.", "We didn't see a new VPN appear.\n\nDisconnect your VPN when we ask, and connect it again in the next dialog; then click Retry. You can also choose it from a list."},
	msgStep2NoneConnected:   {"No hay ninguna VPN conectada.\n\nConecta tu VPN y toca Reintentar.", "No VPN is connected.\n\nConnect your VPN, then click Retry."},
	msgStep2List:            {"¿Cuál es tu VPN? Elige la que conectaste.", "Which one is your VPN? Choose the one you connected."},
	msgStep3Password:        {"Activar la protección.\n\nTu Mac te va a pedir tu contraseña: es la misma que usas para entrar a la Mac. La necesitamos una sola vez, para instalar el servicio que bloquea %s si tu VPN se cae.", "Turn on the protection.\n\nYour Mac will ask for your password: the same one you use to log in to your Mac. We need it only this once, to install the background service that blocks %s if your VPN drops."},
	msgStep3NoPassword:      {"Activar la protección.\n\nVamos a proteger %s con tu VPN. No hace falta tu contraseña: el servicio de leakguard ya está instalado.", "Turn on the protection.\n\nWe will protect %s with your VPN. No password needed: the leakguard background service is already installed."},
	msgAdminPrompt:          {"leakguard necesita tu contraseña una sola vez para instalar el servicio que te protege.", "leakguard needs your password once to install the service that protects you."},
	msgDoneOne:              {"Listo: %s está protegido. Si tu VPN se cae, %s deja de conectarse hasta que vuelva.", "Done: %s is protected. If your VPN drops, %s stops connecting until it is back."},
	msgDoneMany:             {"Listo: %s están protegidos. Si tu VPN se cae, dejan de conectarse hasta que vuelva.", "Done: %s are protected. If your VPN drops, they stop connecting until it is back."},
	msgDoneShield:           {"El escudo lleno en la barra de menú significa que estás protegido.", "A filled shield in the menu bar means you are protected."},
	msgChangeVPNDone:        {"Listo: leakguard ahora usa esta VPN.", "Done: leakguard now uses this VPN."},
	msgActivateFailed:       {"No se pudo activar la protección: %s\n\nPuedes intentarlo de nuevo desde el menú.", "Could not turn on the protection: %s\n\nYou can try again from the menu."},
	msgChangeVPNFailed:      {"No se pudo cambiar de VPN: %s\n\nPuedes intentarlo de nuevo desde el menú.", "Could not change the VPN: %s\n\nYou can try again from the menu."},
	msgWizardFailed:         {"Algo salió mal: %s\n\nPuedes intentarlo de nuevo desde el menú.", "Something went wrong: %s\n\nYou can try again from the menu."},
	msgAnd:                  {"y", "and"},
	msgKindVPN:              {"VPN", "VPN"},
	msgKindIPsec:            {"VPN IPsec", "IPsec VPN"},
	msgKindWireGuard:        {"WireGuard", "WireGuard"},
	msgKindPPP:              {"VPN PPP", "PPP VPN"},
	msgTooltipVersion:       {"%s · versión %s", "%s · version %s"},

	msgUninstallTitle:         {"Desinstalar leakguard", "Uninstall leakguard"},
	msgUninstallConfirm:       {"¿Quieres desinstalar leakguard?\n\nSe quitarán las reglas de protección, el servicio de fondo y la apertura al iniciar sesión. Los servicios que protegías volverán a usar tu conexión normal.\n\nLa app se queda en Aplicaciones: después puedes arrastrarla a la Papelera. Tu Mac te va a pedir tu contraseña.", "Do you want to uninstall leakguard?\n\nThis removes the protection rules, the background service and the login item. The services you protected will use your normal connection again.\n\nThe app stays in Applications: afterwards you can drag it to the Trash. Your Mac will ask for your password."},
	msgButtonUninstall:        {"Desinstalar", "Uninstall"},
	msgUninstallPrompt:        {"leakguard necesita tu contraseña para quitar la protección y el servicio de fondo.", "leakguard needs your password to remove the protection and the background service."},
	msgUninstallCancelled:     {"No se desinstaló nada: leakguard sigue igual que antes.", "Nothing was uninstalled: leakguard keeps working as before."},
	msgUninstallFailed:        {"No se pudo desinstalar leakguard: %s\n\nLa app sigue abriéndose al iniciar sesión. Puedes intentarlo de nuevo desde el menú.", "Could not uninstall leakguard: %s\n\nThe app still opens at login. You can try again from the menu."},
	msgUninstallCleanupFailed: {"leakguard se desinstaló, pero no se pudo quitar la apertura al iniciar sesión: %s\n\nPuedes arrastrar la app a la Papelera.", "leakguard was uninstalled, but the login item could not be removed: %s\n\nYou can drag the app to the Trash."},
	msgUninstallDone:          {"leakguard se desinstaló. Puedes arrastrar la app a la Papelera.", "leakguard was uninstalled. You can drag the app to the Trash."},
}

// Text returns message m in language l, formatted with args when given.
// Any language other than Spanish reads English.
func (l Lang) Text(m Msg, args ...any) string {
	if m < 0 || m >= msgCount {
		return ""
	}
	s := messages[m].en
	if l == Spanish {
		s = messages[m].es
	}
	if len(args) > 0 {
		s = fmt.Sprintf(s, args...)
	}
	return s
}

// list joins names as "A, B and C" in language l.
func (l Lang) list(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " " + l.Text(msgAnd) + " " + names[len(names)-1]
}
