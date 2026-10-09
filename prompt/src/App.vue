<script setup lang="ts">
import { invoke } from '@tauri-apps/api/core';
import { useConfigStore } from '@vasakgroup/plugin-config-manager';
import { WindowFrame } from '@vasakgroup/vue-libvasak';
import { nextTick, onMounted, ref } from 'vue';

const password = ref('');
const error = ref('');
const working = ref(false);
const field = ref<HTMLInputElement | null>(null);
/**
 * La contraseña con la que se inició sesión no abre el llavero: está cifrado
 * con otra, casi siempre la anterior de la cuenta (vasak-keyring#38). Lo que se
 * pide entonces es ésa, y al abrirlo queda cifrado con la de ahora.
 */
const stale = ref(false);
/** Se pidió apartar el llavero y falta confirmarlo. */
const confirmingReset = ref(false);

/**
 * Colours, corner radius and font come from the configuration, the same way
 * every other application gets them: the store writes them onto the document.
 * A dialog asking for the account password has to look like it belongs to the
 * system — one that looks foreign is one nobody should type into.
 */
onMounted(async () => {
	const configStore = useConfigStore();

	// With a deadline, and not for the colours: the field gets focused after
	// this await, so a configuration that never answers would leave the dialog
	// waiting to focus a password box. If the deadline wins, the dialog still
	// works with the shipped defaults, which is the whole point of the catch.
	const PLAZO_CONFIG_MS = 2000;
	try {
		const lectura = configStore.loadConfig();
		// If the deadline wins and the reading fails afterwards, that
		// rejection cannot be left unattended.
		lectura.catch(() => {});
		await Promise.race([lectura, new Promise((resolve) => setTimeout(resolve, PLAZO_CONFIG_MS))]);
	} catch {
		// The shipped defaults are still a Vasak dialog; failing to read the
		// configuration is no reason not to ask for the password.
	}

	try {
		stale.value = await invoke<boolean>('login_password_rejected');
	} catch {
		// Sin respuesta, el diálogo de siempre.
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
		error.value = stale.value
			? 'Esa contraseña tampoco abre el llavero.'
			: 'La contraseña no es correcta.';
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

/**
 * Aparta el llavero que no abre —no lo borra— y empieza uno vacío con la
 * contraseña de ahora. Pide una confirmación: lo guardado deja de estar a mano.
 */
const reset = async () => {
	if (working.value) return;
	if (!confirmingReset.value) {
		confirmingReset.value = true;
		return;
	}

	working.value = true;
	error.value = '';
	try {
		await invoke<string>('reset');
		await invoke('finish', { unlocked: true });
	} catch (reason) {
		error.value = String(reason) || 'El servicio del llavero no respondió.';
		confirmingReset.value = false;
	} finally {
		working.value = false;
	}
};
</script>

<template>
	<!-- El marco es el compartido, y sin barra: esto es un cuadro de diálogo,
	     no una ventana. Se responde —se escribe la contraseña o se cancela—, y
	     un botón de cerrar sería una salida que deja al programa que pidió el
	     secreto esperando. Del marco se queda lo que sí hace falta: que el
	     borde, la esquina y el fondo sean los mismos que los de la ventana que
	     tiene debajo, que es cualquiera.

	     El fondo es el del marco y no uno propio: dos utilidades de fondo sobre
	     el mismo elemento las desempata el orden del CSS generado, no el del
	     atributo, así que un `bg-ui-bg/95` encima del `/80` del marco gana o
	     pierde según el día. -->
	<WindowFrame hide-bar>
		<div class="flex min-w-0 flex-1 select-none flex-col gap-4 p-6">
		<div class="flex flex-col gap-2">
			<h1 class="text-lg font-semibold text-tx-main">
				{{ stale ? 'El llavero sigue con tu contraseña anterior' : 'El llavero está bloqueado' }}
			</h1>
			<p v-if="stale" class="text-sm text-tx-muted" data-stale-explanation>
				La contraseña con la que iniciaste sesión no lo abre: seguramente la cambiaste.
				Escribí la que usabas antes y el llavero queda con la de ahora.
			</p>
			<p v-else class="text-sm text-tx-muted">
				Tus contraseñas guardadas están cifradas con la contraseña de tu cuenta.
				Normalmente se entrega al iniciar sesión.
			</p>
		</div>

		<form class="flex flex-col gap-2" @submit.prevent="submit">
			<label for="password" class="text-xs font-semibold uppercase text-tx-main">
				{{ stale ? 'Contraseña anterior de tu cuenta' : 'Contraseña de tu cuenta' }}
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
			<p v-if="confirmingReset" role="alert" class="text-sm text-tx-main" data-reset-warning>
				Se aparta el llavero actual —no se borra— y empezás uno vacío con tu contraseña de ahora.
				Lo guardado ahí vuelve si después recordás la anterior.
			</p>
		</form>

		<div class="mt-auto flex justify-end gap-2">
			<button
				v-if="stale"
				type="button"
				:disabled="working"
				class="mr-auto rounded-corner px-4 py-2 text-sm text-tx-main hover:bg-ui-surface disabled:opacity-50"
				data-reset
				@click="reset"
			>
				{{ confirmingReset ? 'Apartar y empezar de nuevo' : 'No la recuerdo' }}
			</button>
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
	</WindowFrame>
</template>
