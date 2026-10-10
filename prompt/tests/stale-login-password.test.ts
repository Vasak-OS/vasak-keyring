/**
 * El diálogo del llavero después de un `passwd` (vasak-keyring#38).
 *
 * La contraseña con la que se inició sesión ya no abre el llavero: la base sigue
 * cifrada con la anterior. Pedir «la contraseña de tu cuenta» ahí es pedir la que
 * acaba de fallar, así que el diálogo tiene que decir que lo que hace falta es la
 * **anterior**, y ofrecer una salida si no aparece. Esa salida aparta el llavero,
 * y por eso no puede bastar un clic.
 */

import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils';
import { createPinia, setActivePinia } from 'pinia';
import App from '@/App.vue';
import { argumentos, contestar, fallar, invocaciones, olvidarTodo } from './dobles';

let vista: VueWrapper | null = null;

async function abrir({ loginRechazado }: { loginRechazado: boolean }) {
	contestar('login_password_rejected', loginRechazado);
	vista = mount(App);
	await flushPromises();
	return vista;
}

function boton(dialogo: VueWrapper, texto: string) {
	return dialogo.findAll('button').find((b) => b.text().trim() === texto);
}

/** Lo que recibió cada comando que se invocó, por nombre. */
function loQueRecibio(comando: string) {
	return invocaciones.flatMap((nombre, i) => (nombre === comando ? [argumentos[i]] : []));
}

beforeEach(() => setActivePinia(createPinia()));

afterEach(() => {
	vista?.unmount();
	vista = null;
	olvidarTodo();
});

describe('con la contraseña del inicio de sesión rechazada', () => {
	test('le pregunta al demonio si la contraseña del inicio de sesión fue rechazada', async () => {
		await abrir({ loginRechazado: true });

		expect(invocaciones).toContain('login_password_rejected');
	});

	test('dice que el llavero sigue con la contraseña anterior y pide ésa', async () => {
		const dialogo = await abrir({ loginRechazado: true });

		expect(dialogo.get('h1').text()).toBe('El llavero sigue con tu contraseña anterior');
		expect(dialogo.get('label').text()).toBe('Contraseña anterior de tu cuenta');
		expect(dialogo.find('[data-stale-explanation]').exists()).toBe(true);
	});

	test('ofrece «No la recuerdo»', async () => {
		const dialogo = await abrir({ loginRechazado: true });

		expect(boton(dialogo, 'No la recuerdo')).toBeDefined();
	});

	test('el primer clic en «No la recuerdo» pide confirmar y no aparta nada', async () => {
		const dialogo = await abrir({ loginRechazado: true });

		await boton(dialogo, 'No la recuerdo')?.trigger('click');
		await flushPromises();

		expect(invocaciones).not.toContain('reset');
		expect(invocaciones).not.toContain('finish');
		expect(dialogo.find('[data-reset-warning]').exists()).toBe(true);
		expect(boton(dialogo, 'Apartar y empezar de nuevo')).toBeDefined();
	});

	test('el segundo clic aparta el llavero y cierra el diálogo como desbloqueado', async () => {
		const dialogo = await abrir({ loginRechazado: true });
		contestar('reset', '/tmp/keyring.db.apartada-1');

		await boton(dialogo, 'No la recuerdo')?.trigger('click');
		await flushPromises();
		await boton(dialogo, 'Apartar y empezar de nuevo')?.trigger('click');
		await flushPromises();

		expect(invocaciones.filter((c) => c === 'reset')).toHaveLength(1);
		// `reset` no lleva contraseña: el demonio usa la del inicio de sesión.
		expect(loQueRecibio('reset')).toEqual([undefined]);
		expect(loQueRecibio('finish')).toEqual([{ unlocked: true }]);
		expect(invocaciones.indexOf('reset')).toBeLessThan(invocaciones.indexOf('finish'));
	});

	test('si apartar falla, se ve el motivo y el diálogo no se cierra', async () => {
		const dialogo = await abrir({ loginRechazado: true });
		fallar('reset', 'el llavero está abierto: no hay nada que apartar');

		await boton(dialogo, 'No la recuerdo')?.trigger('click');
		await flushPromises();
		await boton(dialogo, 'Apartar y empezar de nuevo')?.trigger('click');
		await flushPromises();

		expect(invocaciones).not.toContain('finish');
		expect(dialogo.get('[role="alert"]').text()).toBe(
			'el llavero está abierto: no hay nada que apartar',
		);
		// Y volver a intentarlo pide confirmar otra vez.
		expect(boton(dialogo, 'No la recuerdo')).toBeDefined();
	});

	test('una contraseña anterior que tampoco abre lo dice así', async () => {
		const dialogo = await abrir({ loginRechazado: true });
		contestar('unlock', false);

		await dialogo.get('input').setValue('la-que-no-es');
		await dialogo.get('form').trigger('submit');
		await flushPromises();

		expect(dialogo.get('[role="alert"]').text()).toBe('Esa contraseña tampoco abre el llavero.');
		expect(invocaciones).not.toContain('finish');
	});
});

describe('sin contraseña del inicio de sesión rechazada', () => {
	test('es el diálogo de siempre, sin la salida de apartar el llavero', async () => {
		const dialogo = await abrir({ loginRechazado: false });

		expect(dialogo.get('h1').text()).toBe('El llavero está bloqueado');
		expect(dialogo.get('label').text()).toBe('Contraseña de tu cuenta');
		expect(boton(dialogo, 'No la recuerdo')).toBeUndefined();
		expect(dialogo.find('[data-stale-explanation]').exists()).toBe(false);
	});

	test('si el demonio no contesta, también es el diálogo de siempre', async () => {
		fallar('login_password_rejected', 'sin bus');
		const dialogo = await abrir({ loginRechazado: true });

		expect(dialogo.get('h1').text()).toBe('El llavero está bloqueado');
		expect(boton(dialogo, 'No la recuerdo')).toBeUndefined();
	});
});
