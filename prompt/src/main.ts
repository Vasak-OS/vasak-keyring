import { createPinia } from 'pinia';
import { createApp } from 'vue';
import App from '@/App.vue';
import SshView from '@/SshView.vue';
import '@/assets/main.css';

// Dos diálogos, un solo paquete: desbloquear el llavero y desbloquear una
// clave SSH son la misma ventana con otro texto. La dirección dice cuál es.
const isSsh = window.location.hash.startsWith('#/ssh');

const app = createApp(isSsh ? SshView : App);
const pinia = createPinia();

app.use(pinia);

app.mount('#app');
