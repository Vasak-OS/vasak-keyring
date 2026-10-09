/**
 * Qué diálogo se abre según la dirección.
 *
 * Los cuatro diálogos son un solo paquete y la ventana elige por el `#` de la
 * dirección. La de git se abre en `index.html#/git`: si `main.ts` no la
 * reconoce, git recibe el diálogo del llavero, que le pide la contraseña
 * maestra a quien sólo quería hacer un `git push`.
 */

import { afterAll, beforeAll, expect, test } from 'bun:test';
import { flushPromises } from '@vue/test-utils';
import { contestar, invocaciones, olvidarTodo } from './dobles';

beforeAll(async () => {
	window.happyDOM.setURL('http://localhost/index.html#/git');
	document.body.innerHTML = '<div id="app"></div>';
	contestar('git_request', { field: 'username', host: 'github.com', username: null });

	// `main.ts` monta al importarse.
	await import('@/main');
	await flushPromises();
});

afterAll(() => {
	document.body.innerHTML = '';
	olvidarTodo();
});

test('#/git abre el diálogo de git', () => {
	expect(document.querySelector('h1')?.textContent).toBe('Iniciar sesión en git');
	expect(invocaciones).toContain('git_request');
});
