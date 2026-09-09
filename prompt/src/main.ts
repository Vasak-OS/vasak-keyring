import { createPinia } from 'pinia';
import { createApp } from 'vue';
import App from '@/App.vue';
import GpgView from '@/GpgView.vue';
import SshView from '@/SshView.vue';
import { disableNativeContextMenu } from '@/tools/native-menu';
import '@/assets/main.css';

// Los dos diálogos comparten este archivo, así que apagar el menú del motor
// del navegador acá los cubre a ambos.
disableNativeContextMenu();

// Tres diálogos, un solo paquete: desbloquear el llavero, desbloquear una
// clave SSH y la contraseña que pide GPG son la misma ventana con otro texto.
// La dirección dice cuál es.
const hash = window.location.hash;
const vista = hash.startsWith('#/ssh') ? SshView : hash.startsWith('#/gpg') ? GpgView : App;

const app = createApp(vista);
const pinia = createPinia();

app.use(pinia);

app.mount('#app');
