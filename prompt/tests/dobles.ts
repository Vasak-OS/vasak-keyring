/**
 * Los dobles de lo que sólo existe adentro de la ventana de Tauri.
 *
 * Sin ellos, importar cualquiera de los tres diálogos falla en la primera
 * línea: el marco pide iconos, escucha el cambio de tema y lee la configuración
 * del escritorio.
 */

export const invocaciones: string[] = [];
const respuestas = new Map<string, unknown>();

export function contestar(comando: string, valor: unknown) {
	respuestas.set(comando, valor);
}

export async function invoke(comando: string) {
	invocaciones.push(comando);
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
	laVentanaRecibio.length = 0;
	respuestas.clear();
}
