<script setup lang="ts">
import { invoke } from '@tauri-apps/api/core';
import { useConfigStore } from '@vasakgroup/plugin-config-manager';
import { WindowFrame } from '@vasakgroup/vue-libvasak';
import { computed, nextTick, onMounted, ref } from 'vue';

interface GitPrompt {
	field: 'username' | 'password' | 'certificate';
	host: string;
	username: string | null;
}

const request = ref<GitPrompt | null>(null);
const value = ref('');
const working = ref(false);
const field = ref<HTMLInputElement | null>(null);

const asksCertificate = computed(() => request.value?.field === 'certificate');
// Las dos se escriben ocultas; cambia lo que se le dice a quien la escribe.
const asksPassword = computed(() => request.value?.field === 'password' || asksCertificate.value);

/**
 * Del otro lado hay un `git` esperando, así que primero se pide lo que hay que
 * preguntar y recién después se carga el tema, igual que en el diálogo de SSH.
 */
onMounted(async () => {
	try {
		request.value = await invoke<GitPrompt>('git_request');
	} catch {
		request.value = { field: 'password', host: '', username: null };
	}

	await nextTick();
	field.value?.focus();

	try {
		const configStore = useConfigStore();
		await configStore.loadConfig();
	} catch {
		// Un diálogo con los colores por omisión sigue siendo un diálogo de Vasak.
	}
});

const cancel = () => invoke('git_cancel');

const submit = async () => {
	if (!value.value || working.value) return;
	working.value = true;
	// No vuelve: el proceso le entrega la respuesta a git y termina.
	await invoke('git_answer', { value: value.value }).catch(() => {
		working.value = false;
	});
};
</script>

<template>
	<!-- El mismo marco sin barra que los otros dos diálogos: se responde o se
	     cancela, y no hay un botón de cerrar que deje a git esperando. -->
	<WindowFrame hide-bar>
		<div class="flex min-w-0 flex-1 select-none flex-col gap-4 p-6">
		<div class="flex flex-col gap-2">
			<h1 class="text-lg font-semibold text-tx-main">Iniciar sesión en git</h1>
			<p v-if="asksCertificate" class="text-sm text-tx-muted">
				El certificado
				<span class="font-medium text-tx-main break-all">{{ request?.host }}</span>
				está protegido con una contraseña.
			</p>
			<p v-else class="text-sm text-tx-muted">
				<span class="font-medium text-tx-main">{{ request?.host || 'El servidor' }}</span>
				pide
				<template v-if="asksPassword">
					la contraseña o el token de
					<span class="font-medium text-tx-main">{{ request?.username ?? 'tu usuario' }}</span>.
				</template>
				<template v-else>tu nombre de usuario.</template>
			</p>
		</div>

		<form class="flex flex-col gap-3" @submit.prevent="submit">
			<div class="flex flex-col gap-2">
				<label for="credential" class="text-xs font-semibold uppercase text-tx-main">
					{{ asksCertificate ? 'Contraseña del certificado' : asksPassword ? 'Contraseña o token' : 'Usuario' }}
				</label>
				<input
					id="credential"
					ref="field"
					v-model="value"
					:type="asksPassword ? 'password' : 'text'"
					:autocomplete="asksPassword ? 'current-password' : 'username'"
					:disabled="working"
					class="rounded-corner border border-ui-border bg-ui-bg/80 p-2 text-tx-main outline-none focus:border-transparent focus:ring-2 focus:ring-primary disabled:opacity-50"
				/>
			</div>

			<!-- Lo guarda git en el llavero cuando el servidor lo acepta, así que
			     una contraseña mal escrita no queda recordada. -->
			<p v-if="asksPassword" class="text-sm text-tx-muted">
				Si funciona, queda guardada en el llavero.
			</p>
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
				:disabled="working || !value"
				class="rounded-corner bg-primary px-4 py-2 text-sm font-semibold text-tx-on-primary hover:bg-secondary disabled:opacity-50"
				@click="submit"
			>
				{{ asksPassword ? 'Iniciar sesión' : 'Continuar' }}
			</button>
		</div>
		</div>
	</WindowFrame>
</template>
