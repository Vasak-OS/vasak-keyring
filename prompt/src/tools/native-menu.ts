/**
 * Apaga el menú del clic derecho que dibuja el motor del navegador.
 *
 * WebKit ofrece «Recargar», «Inspeccionar elemento» y «Abrir enlace en una
 * ventana nueva» sobre un diálogo que no es una página web. Nada de eso
 * pertenece acá, y recargar es lo peor de las tres: del otro lado hay un
 * llavero bloqueado o un `ssh` esperando la frase de una clave, y la ventana
 * volvía a empezar sola con el campo vacío sin que nadie lo pidiera.
 *
 * Este diálogo no pone un menú propio en su lugar, y es a propósito:
 *
 * * No hay nada que ofrecer sobre un secreto. Un ítem que copie la contraseña
 *   al portapapeles la dejaría legible para cualquier programa de la sesión, y
 *   ninguna comodidad justifica eso.
 * * Pegar tampoco necesita menú: el teclado ya lo hace (Ctrl+V, Shift+Insert)
 *   y esto no lo toca, porque prevenir el menú es prevenir un `contextmenu`,
 *   no un `keydown`. Para ofrecerlo con el mouse habría que darle a este
 *   diálogo permiso para **leer** el portapapeles, y el diálogo que pide la
 *   contraseña de la cuenta es el último lugar donde conviene agregar eso.
 *
 * Prevenir el comportamiento por defecto no cancela los escuchas de la página,
 * así que si alguna vez hace falta un menú propio, este archivo no lo estorba.
 */
export function disableNativeContextMenu(): void {
	// En captura y sobre el documento: el evento se ataja antes de llegar a
	// cualquier elemento, incluidos los que todavía no existen.
	document.addEventListener('contextmenu', (event) => event.preventDefault(), {
		capture: true,
	});
}
