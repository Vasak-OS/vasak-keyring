/**
 * Los tres diálogos del llavero, con el marco compartido y sin barra.
 *
 * Desbloquear el llavero, desbloquear una clave SSH y la frase que pide GPG son
 * la misma ventana con otro texto, y las tres dibujaban su propio borde, su
 * propia esquina y su propio fondo. Aparecen encima de lo que sea que estés
 * haciendo, así que si su esquina no es la misma que la de la ventana que
 * tienen debajo, se ve.
 *
 * Sin barra y por lo tanto sin ningún botón de ventana: acá la ventana **se
 * responde**. Cerrarla dejaría al programa que pidió el secreto esperando, y la
 * pregunta sin respuesta sin que nadie se entere.
 */

import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { WindowControls, WindowFrame } from '@vasakgroup/vue-libvasak';
import { mount, type VueWrapper } from '@vue/test-utils';
import { createPinia, setActivePinia } from 'pinia';
import App from '@/App.vue';
import GpgView from '@/GpgView.vue';
import SshView from '@/SshView.vue';
import { laVentanaRecibio, olvidarTodo } from './dobles';

/** Los tres, para no escribir tres veces la misma prueba. */
const DIALOGOS = [
	['el del llavero', App],
	['el de SSH', SshView],
	['el de GPG', GpgView],
] as const;

let vista: VueWrapper | null = null;

beforeEach(() => setActivePinia(createPinia()));

afterEach(() => {
	vista?.unmount();
	vista = null;
	olvidarTodo();
});

describe.each(DIALOGOS)('%s', (_nombre, Componente) => {
	test('usa el marco compartido y no uno dibujado a mano', () => {
		vista = mount(Componente);

		expect(vista.findComponent(WindowFrame).exists()).toBe(true);
		// `rounded-corner-window` es la esquina de la ventana y sale del marco.
		// Con dos, el borde y el fondo se dibujan dos veces y se ven los dos.
		expect(vista.findAll('.rounded-corner-window').length).toBe(1);
	});

	test('va sin barra, así que no tiene ningún botón de ventana', () => {
		vista = mount(Componente);

		expect(vista.findComponent(WindowFrame).props('hideBar')).toBe(true);
		expect(vista.findComponent(WindowControls).exists()).toBe(false);
	});

	test('y nada le pide a la ventana que se cierre', () => {
		// Lo que se comprueba no es que no haya botón sino que no haya forma: un
		// `close()` colgado de una tecla o de un clic en el fondo sería el mismo
		// agujero con otra cara, y acá el agujero es dejar al programa que pidió
		// el secreto esperando para siempre.
		vista = mount(Componente);

		for (const boton of vista.findAll('button')) boton.trigger('click');

		expect(laVentanaRecibio).toEqual([]);
	});
});
