/**
 * Lo que tiene que estar listo antes de la primera prueba.
 *
 * El DOM, el complemento que compila los `.vue` —Bun los trata como un archivo
 * suelto y lo que se importa sin él es la ruta— y los dobles de Tauri, que los
 * componentes llaman al importarse.
 */

import { GlobalRegistrator } from '@happy-dom/global-registrator';
import { mock } from 'bun:test';
import './complemento-vue';
import {
	getCurrentWindow,
	getIconSource,
	getSymbolSource,
	invoke,
	listen,
	readConfig,
	useConfigStore,
} from './dobles';

GlobalRegistrator.register();

// El doble **encima** del módulo de verdad, no en su lugar. Reemplazarlo entero
// deja sin exportar lo que no se nombra acá —`SERIALIZE_TO_IPC_FN`, por
// ejemplo— y ahí lo que falla es el import y no la prueba.
const core = await import('@tauri-apps/api/core');
const eventos = await import('@tauri-apps/api/event');
const ventana = await import('@tauri-apps/api/window');
const configuracion = await import('@vasakgroup/plugin-config-manager');
const iconos = await import('@vasakgroup/plugin-vicons');

mock.module('@tauri-apps/api/core', () => ({ ...core, invoke }));
mock.module('@tauri-apps/api/event', () => ({ ...eventos, listen }));
mock.module('@tauri-apps/api/window', () => ({ ...ventana, getCurrentWindow }));
mock.module('@vasakgroup/plugin-vicons', () => ({ ...iconos, getIconSource, getSymbolSource }));
mock.module('@vasakgroup/plugin-config-manager', () => ({
	...configuracion,
	useConfigStore,
	readConfig,
}));
