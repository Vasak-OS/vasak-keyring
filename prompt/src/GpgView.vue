<script setup lang="ts">
import { invoke } from '@tauri-apps/api/core';
import { useConfigStore } from '@vasakgroup/plugin-config-manager';
import { computed, nextTick, onMounted, ref } from 'vue';

/**
 * Lo que `gpg-agent` quiere preguntar.
 *
 * Los textos los escribe él y llegan tal cual: la descripción suele traer la
 * huella de la clave y para qué se la está usando, que es la única forma que
 * tiene la persona de saber qué está por desbloquear.
 */
interface GpgRequest {
	/** `frase`, `confirmar`, `aviso` o `error`. */
	modo: string;
	descripcion: string;
	etiqueta: string;
	titulo: string;
	/** Por qué falló el intento anterior, si hubo uno. */
	error: string;
}

const request = ref<GpgRequest | null>(null);
const passphrase = ref('');
const working = ref(false);
const field = ref<HTMLInputElement | null>(null);
const aceptar = ref<HTMLButtonElement | null>(null);

const pideFrase = computed(() => request.value?.modo === 'frase');
const esAviso = computed(() => request.value?.modo === 'aviso');
const esError = computed(() => request.value?.modo === 'error');

const titulo = computed(
	() => request.value?.titulo || (pideFrase.value ? 'Contraseña de GPG' : 'GPG')
);
const etiqueta = computed(() => request.value?.etiqueta || 'Contraseña');

/**
 * Del otro lado hay un `gpg-agent` esperando, así que primero se pide qué hay
 * que preguntar y recién después se carga el tema: si la configuración no se
 * puede leer, el diálogo aparece igual con los colores por omisión.
 */
onMounted(async () => {
	try {
		request.value = await invoke<GpgRequest>('gpg_request');
	} catch {
		// Falla cerrado. Antes se caía a pedir una frase con la descripción
		// vacía: una ventana que pide la contraseña de una clave privada sin
		// poder decir de cuál se trata. Eso no se pregunta — se explica y se
		// ofrece cancelar, que es lo único honesto cuando no sabemos qué
		// estaríamos autorizando.
		request.value = {
			modo: 'error',
			descripcion: '',
			etiqueta: '',
			titulo: 'GPG',
			error: 'No se pudo leer qué está pidiendo GPG. Cancelá y volvé a intentarlo.',
		};
	}

	await nextTick();
	// En un aviso o una confirmación no hay campo donde escribir: el foco va al
	// botón que responde, así se puede contestar sin tocar el ratón.
	(field.value ?? aceptar.value)?.focus();

	try {
		const configStore = useConfigStore();
		await configStore.loadConfig();
	} catch {
		// Un diálogo con los colores por omisión sigue siendo un diálogo de Vasak.
	}
});

const cancel = () => invoke('gpg_cancel');

const submit = async () => {
	if (working.value) return;
	if (pideFrase.value && !passphrase.value) return;
	working.value = true;
	// No vuelve: el proceso entrega la respuesta y termina.
	await invoke('gpg_answer', { passphrase: passphrase.value }).catch(() => {
		working.value = false;
	});
};
</script>

<template>
	<div
		class="h-screen w-screen select-none rounded-corner-window border border-ui-border bg-ui-bg/95 p-6 flex flex-col gap-4"
	>
		<div class="flex flex-col gap-2">
			<h1 class="text-lg font-semibold text-tx-main">{{ titulo }}</h1>
			<!-- El texto lo escribe el agente y puede traer saltos de línea: se
			     respetan, porque ahí es donde separa la huella de la clave del
			     motivo por el que la pide. -->
			<p v-if="request?.descripcion" class="whitespace-pre-line text-sm text-tx-muted">
				{{ request.descripcion }}
			</p>
		</div>

		<!-- El error del intento anterior. Va arriba del campo y no abajo: es la
		     razón por la que la ventana volvió a aparecer. -->
		<p
			v-if="request?.error"
			class="rounded-corner border border-status-error/40 bg-status-error/10 p-2 text-sm text-status-error"
		>
			{{ request.error }}
		</p>

		<form v-if="pideFrase" class="flex flex-col gap-3" @submit.prevent="submit">
			<div class="flex flex-col gap-2">
				<label for="passphrase" class="text-xs font-semibold uppercase text-tx-main">
					{{ etiqueta }}
				</label>
				<input
					id="passphrase"
					ref="field"
					v-model="passphrase"
					type="password"
					autocomplete="current-password"
					:disabled="working"
					class="rounded-corner border border-ui-border bg-ui-bg/80 p-2 text-tx-main outline-none focus:border-transparent focus:ring-2 focus:ring-primary disabled:opacity-50"
				/>
			</div>
		</form>

		<div class="mt-auto flex justify-end gap-2">
			<!-- Un aviso de una sola opción no se puede rechazar: mostrar
			     «Cancelar» ahí sería ofrecer una salida que no existe. -->
			<button
				v-if="!esAviso"
				type="button"
				:disabled="working"
				class="rounded-corner border border-ui-border px-4 py-2 text-sm text-tx-main hover:bg-ui-surface disabled:opacity-50"
				@click="cancel"
			>
				Cancelar
			</button>
			<button
				v-if="!esError"
				ref="aceptar"
				type="button"
				:disabled="working || (pideFrase && !passphrase)"
				class="rounded-corner bg-primary px-4 py-2 text-sm font-semibold text-tx-on-primary hover:bg-secondary disabled:opacity-50"
				@click="submit"
			>
				{{ pideFrase ? (working ? 'Desbloqueando…' : 'Desbloquear') : 'Aceptar' }}
			</button>
		</div>
	</div>
</template>
