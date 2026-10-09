/**
 * Los dobles de lo que sólo existe adentro de la ventana de Tauri.
 *
 * Sin ellos, importar cualquiera de los diálogos falla en la primera
 * línea: el marco pide iconos, escucha el cambio de tema y lee la configuración
 * del escritorio.
 */

export const invocaciones: string[] = [];
/** Lo que se le pasó a cada comando, en el mismo orden que `invocaciones`. */
export const argumentos: unknown[] = [];
const respuestas = new Map<string, unknown>();
const fallos = new Map<string, string>();

export function contestar(comando: string, valor: unknown) {
	respuestas.set(comando, valor);
}

/** El comando falla con este motivo, como un `Err` del lado de Rust. */
export function fallar(comando: string, motivo: string) {
	fallos.set(comando, motivo);
}

export async function invoke(comando: string, args?: unknown) {
	invocaciones.push(comando);
	argumentos.push(args);
	const motivo = fallos.get(comando);
	if (motivo !== undefined) throw motivo;
	return respuestas.get(comando);
}

export const laVentanaRecibio: string[] = [];

export function getCurrentWindow() {
	return {
		label: 'main',
		minimize: async () => void laVentanaRecibio.push('minimize'),
		toggleMaximize: async () => void laVentanaRecibio.push('toggleMaximize'),
		close: async () => void laVentanaRecibio.push('close'),
	};
}

export async function readConfig() {
	return {};
}

export function useConfigStore() {
	return { config: {}, loadConfig: async () => {} };
}

export async function listen(_nombre: string, _manejador: () => unknown) {
	return () => {};
}

export async function getIconSource(_nombre: string) {
	return 'icono.png';
}

export async function getSymbolSource(_nombre: string) {
	return 'simbolo.png';
}

export function olvidarTodo() {
	invocaciones.length = 0;
	argumentos.length = 0;
	laVentanaRecibio.length = 0;
	respuestas.clear();
	fallos.clear();
}
