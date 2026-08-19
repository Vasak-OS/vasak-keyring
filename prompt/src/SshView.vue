<script setup lang="ts">
import { invoke } from '@tauri-apps/api/core';
import { useConfigStore } from '@vasakgroup/plugin-config-manager';
import type { Store } from 'pinia';
import { nextTick, onMounted, ref } from 'vue';

interface SshRequest {
	key_name: string;
	key_path: string | null;
	prompt: string;
}

const request = ref<SshRequest | null>(null);
const passphrase = ref('');
const remember = ref(true);
const working = ref(false);
const field = ref<HTMLInputElement | null>(null);

/**
 * Del otro lado hay un `ssh` esperando una respuesta, así que primero se pide
 * lo que hay que preguntar y recién después se carga el tema: si la
 * configuración no se puede leer, el diálogo aparece igual con los colores por
 * omisión.
 */
onMounted(async () => {
	try {
		request.value = await invoke<SshRequest>('ssh_request');
	} catch {
		request.value = { key_name: 'SSH', key_path: null, prompt: '' };
	}

	await nextTick();
	field.value?.focus();

	try {
		const configStore = useConfigStore() as Store<
			'config',
			{ config: any; loadConfig: () => Promise<void> }
		>;
		await configStore.loadConfig();
	} catch {
		// Un diálogo con los colores por omisión sigue siendo un diálogo de Vasak.
	}
});

const cancel = () => invoke('ssh_cancel');

const submit = async () => {
	if (!passphrase.value || working.value) return;
	working.value = true;
	// No vuelve: el proceso entrega la frase a ssh y termina.
	await invoke('ssh_answer', {
		passphrase: passphrase.value,
		remember: remember.value && !!request.value?.key_path,
	}).catch(() => {
		working.value = false;
	});
};
</script>

<template>
	<div
		class="h-screen w-screen select-none rounded-corner-window border border-ui-border bg-ui-bg/95 p-6 flex flex-col gap-4"
	>
		<div class="flex flex-col gap-2">
			<h1 class="text-lg font-semibold text-tx-main">Desbloquear la clave SSH</h1>
			<p class="text-sm text-tx-muted">
				La clave <span class="font-medium text-tx-main">{{ request?.key_name ?? 'SSH' }}</span>
				está protegida con una frase de contraseña.
			</p>
		</div>

		<form class="flex flex-col gap-3" @submit.prevent="submit">
			<div class="flex flex-col gap-2">
				<label for="passphrase" class="text-xs font-semibold uppercase text-tx-main">
					Frase de la clave
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

			<!-- Guardarla es el punto de todo esto: el llavero lo abre tu inicio
			     de sesión, así que a partir de la próxima vez no se pregunta más. -->
			<label
				v-if="request?.key_path"
				class="flex items-center gap-2 text-sm text-tx-muted"
			>
				<input v-model="remember" type="checkbox" :disabled="working" class="accent-primary" />
				Recordarla en el llavero
			</label>
		</form>

		<div class="mt-auto flex justify-end gap-2">
			<button
				type="button"
				:disabled="working"
				class="rounded-corner border border-ui-border px-4 py-2 text-sm text-tx-main hover:bg-ui-surface disabled:opacity-50"
				@click="cancel"
			>
				Cancelar
			</button>
			<button
				type="button"
				:disabled="working || !passphrase"
				class="rounded-corner bg-primary px-4 py-2 text-sm font-semibold text-tx-on-primary hover:bg-secondary disabled:opacity-50"
				@click="submit"
			>
				{{ working ? 'Desbloqueando…' : 'Desbloquear' }}
			</button>
		</div>
	</div>
</template>
