<script setup lang="ts">
import { invoke } from '@tauri-apps/api/core';
import { useConfigStore } from '@vasakgroup/plugin-config-manager';
import type { Store } from 'pinia';
import { nextTick, onMounted, ref } from 'vue';

const password = ref('');
const error = ref('');
const working = ref(false);
const field = ref<HTMLInputElement | null>(null);

/**
 * Colours, corner radius and font come from the configuration, the same way
 * every other application gets them: the store writes them onto the document.
 * A dialog asking for the account password has to look like it belongs to the
 * system — one that looks foreign is one nobody should type into.
 */
onMounted(async () => {
	const configStore = useConfigStore() as Store<
		'config',
		{ config: any; loadConfig: () => Promise<void> }
	>;

	try {
		await configStore.loadConfig();
	} catch {
		// The shipped defaults are still a Vasak dialog; failing to read the
		// configuration is no reason not to ask for the password.
	}

	await nextTick();
	field.value?.focus();
});

const cancel = () => invoke('finish', { unlocked: false });

const submit = async () => {
	if (!password.value || working.value) return;

	working.value = true;
	error.value = '';

	try {
		if (await invoke<boolean>('unlock', { password: password.value })) {
			await invoke('finish', { unlocked: true });
			return;
		}

		// A refusal is about this password, not about the keyring being broken:
		// the answer is to try again, so the field is what gets the focus.
		error.value = 'La contraseña no es correcta.';
		password.value = '';
		await nextTick();
		field.value?.focus();
	} catch (reason) {
		// After three wrong passwords the daemon stops answering for a while and
		// says so. That is worth reading as written, instead of being flattened
		// into "it did not answer" — which would send someone looking for a
		// problem that is not there.
		error.value = String(reason) || 'El servicio del llavero no respondió.';
		password.value = '';
	} finally {
		working.value = false;
	}
};
</script>

<template>
	<div
		class="h-screen w-screen select-none rounded-corner-window border border-ui-border bg-ui-bg/95 p-6 flex flex-col gap-4"
	>
		<div class="flex flex-col gap-2">
			<h1 class="text-lg font-semibold text-tx-main">El llavero está bloqueado</h1>
			<p class="text-sm text-tx-muted">
				Tus contraseñas guardadas están cifradas con la contraseña de tu cuenta.
				Normalmente se entrega al iniciar sesión.
			</p>
		</div>

		<form class="flex flex-col gap-2" @submit.prevent="submit">
			<label for="password" class="text-xs font-semibold uppercase text-tx-main">
				Contraseña de tu cuenta
			</label>
			<input
				id="password"
				ref="field"
				v-model="password"
				type="password"
				autocomplete="current-password"
				:disabled="working"
				class="rounded-corner border border-ui-border bg-ui-bg/80 p-2 text-tx-main outline-none focus:border-transparent focus:ring-2 focus:ring-primary disabled:opacity-50"
			/>
			<p v-if="error" role="alert" class="text-sm text-status-error">{{ error }}</p>
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
				:disabled="working || !password"
				class="rounded-corner bg-primary px-4 py-2 text-sm font-semibold text-tx-on-primary hover:bg-secondary disabled:opacity-50"
				@click="submit"
			>
				{{ working ? 'Desbloqueando…' : 'Desbloquear' }}
			</button>
		</div>
	</div>
</template>
