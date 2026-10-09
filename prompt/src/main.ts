import { createPinia } from 'pinia';
import { createApp } from 'vue';
import App from '@/App.vue';
import GitView from '@/GitView.vue';
import GpgView from '@/GpgView.vue';
import SshView from '@/SshView.vue';
import { disableNativeContextMenu } from '@/tools/native-menu';
import '@/assets/main.css';

// Los dos diálogos comparten este archivo, así que apagar el menú del motor
// del navegador acá los cubre a ambos.
disableNativeContextMenu();

// Cuatro diálogos, un solo paquete: desbloquear el llavero, desbloquear una
// clave SSH, la contraseña que pide GPG y el usuario o la contraseña de un
// remoto de git son la misma ventana con otro texto. La dirección dice cuál es.
const viewsByHash = [
	['#/ssh', SshView],
	['#/gpg', GpgView],
	['#/git', GitView],
] as const;
const hash = window.location.hash;
const vista = viewsByHash.find(([prefix]) => hash.startsWith(prefix))?.[1] ?? App;

const app = createApp(vista);
const pinia = createPinia();

app.use(pinia);

app.mount('#app');
