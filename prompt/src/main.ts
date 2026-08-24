import { createPinia } from 'pinia';
import { createApp } from 'vue';
import App from '@/App.vue';
import SshView from '@/SshView.vue';
import { disableNativeContextMenu } from '@/tools/native-menu';
import '@/assets/main.css';

// Los dos diálogos comparten este archivo, así que apagar el menú del motor
// del navegador acá los cubre a ambos.
disableNativeContextMenu();

// Dos diálogos, un solo paquete: desbloquear el llavero y desbloquear una
// clave SSH son la misma ventana con otro texto. La dirección dice cuál es.
const isSsh = window.location.hash.startsWith('#/ssh');

const app = createApp(isSsh ? SshView : App);
const pinia = createPinia();

app.use(pinia);

app.mount('#app');
