/**
 * El diálogo que contesta a git cuando pide el usuario o la contraseña de un
 * remoto por HTTPS.
 *
 * Del otro lado hay un `git push` esperando. Lo que se escribe acá va derecho
 * al servidor: si el campo de la contraseña se viera, o si lo escrito no le
 * llegara a git, o si cancelar no le avisara, quien está en la terminal se
 * queda mirando un proceso colgado o una contraseña en pantalla.
 */

import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils';
import { createPinia, setActivePinia } from 'pinia';
import GitView from '@/GitView.vue';
import { argumentos, contestar, invocaciones, olvidarTodo } from './dobles';

const PEDIDO_DE_USUARIO = { field: 'username', host: 'github.com', username: null };
const PEDIDO_DE_CONTRASENA = {
	field: 'password',
	host: 'gitlab.example.com:8443',
	username: 'pato',
};

const PEDIDO_DE_CERTIFICADO = {
	field: 'certificate',
	host: '/home/pato/cliente.p12',
	username: null,
};

let vista: VueWrapper | null = null;

async function abrir(pedido: unknown) {
	contestar('git_request', pedido);
	vista = mount(GitView);
	await flushPromises();
	return vista;
}

function boton(dialogo: VueWrapper, texto: string) {
	const encontrado = dialogo.findAll('button').find((b) => b.text().trim() === texto);
	if (!encontrado) throw new Error(`no hay un botón «${texto}»`);
	return encontrado;
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

describe('el diálogo de git', () => {
	test('le pregunta a la ventana qué pidió git', async () => {
		await abrir(PEDIDO_DE_USUARIO);

		expect(invocaciones).toContain('git_request');
	});

	test('un pedido de usuario se contesta en un campo de texto y dice el servidor', async () => {
		const dialogo = await abrir(PEDIDO_DE_USUARIO);

		expect(dialogo.get('input').attributes('type')).toBe('text');
		expect(dialogo.text()).toContain('github.com');
		expect(dialogo.text()).toContain('nombre de usuario');
	});

	test('un pedido de contraseña se escribe oculto y dice de quién y para qué servidor', async () => {
		const dialogo = await abrir(PEDIDO_DE_CONTRASENA);

		expect(dialogo.get('input').attributes('type')).toBe('password');
		expect(dialogo.text()).toContain('pato');
		expect(dialogo.text()).toContain('gitlab.example.com:8443');
	});

	test('lo que se escribe le llega a git al enviar', async () => {
		const dialogo = await abrir(PEDIDO_DE_CONTRASENA);

		await dialogo.get('input').setValue('ghp_un-token');
		await boton(dialogo, 'Iniciar sesión').trigger('click');

		expect(loQueRecibio('git_answer')).toEqual([{ value: 'ghp_un-token' }]);
		expect(invocaciones).not.toContain('git_cancel');
	});

	test('Enter en el campo también envía', async () => {
		const dialogo = await abrir(PEDIDO_DE_USUARIO);

		await dialogo.get('input').setValue('pato');
		await dialogo.get('form').trigger('submit');

		expect(loQueRecibio('git_answer')).toEqual([{ value: 'pato' }]);
	});

	test('sin nada escrito no se le manda a git una respuesta vacía', async () => {
		const dialogo = await abrir(PEDIDO_DE_USUARIO);

		await boton(dialogo, 'Continuar').trigger('click');
		await dialogo.get('form').trigger('submit');

		expect(invocaciones).not.toContain('git_answer');
	});

	test('cancelar le avisa a git que no hay respuesta', async () => {
		const dialogo = await abrir(PEDIDO_DE_CONTRASENA);

		await dialogo.get('input').setValue('a medio escribir');
		await boton(dialogo, 'Cancelar').trigger('click');

		expect(invocaciones).toContain('git_cancel');
		expect(invocaciones).not.toContain('git_answer');
	});

	test('la contraseña de un certificado se escribe oculta y dice de qué archivo es', async () => {
		const dialogo = await abrir(PEDIDO_DE_CERTIFICADO);
		const texto = dialogo.text().replace(/\s+/g, ' ');

		expect(dialogo.get('input').attributes('type')).toBe('password');
		expect(dialogo.get('label').text()).toBe('Contraseña del certificado');
		expect(texto).toContain(
			'El certificado /home/pato/cliente.p12 está protegido con una contraseña.'
		);
	});
});
