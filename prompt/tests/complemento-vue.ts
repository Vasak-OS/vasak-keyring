/**
 * Compilar los componentes de un solo archivo para `bun test`.
 *
 * Bun no entiende `.vue`: los trata como un archivo suelto y devuelve su ruta
 * como una cadena. Importar un componente «funcionaba» —la importación no
 * fallaba— pero lo que llegaba era texto, y montarlo reventaba adentro de
 * `@vue/test-utils` con un error que no nombra a Vue por ningún lado.
 *
 * Así que se compila acá, con el mismo `@vue/compiler-sfc` que usa Vite, y
 * queda registrado como complemento de Bun desde `tests/preparar.ts`.
 *
 * # Qué se compila y qué no
 *
 * El guión y la plantilla, que son lo que las pruebas montan y consultan. Los
 * estilos se descartan: son Tailwind sobre variables del tema, no llegan a
 * `happy-dom` con nada que aplicarles, y compilarlos sólo agregaría un paso
 * lento que ninguna prueba mira. Las clases del elemento se siguen pudiendo
 * comprobar porque están en la plantilla, no en el CSS.
 */

import { plugin } from 'bun';
import { compileScript, compileTemplate, parse, rewriteDefault } from 'vue/compiler-sfc';

/**
 * Un identificador estable por archivo.
 *
 * `compileScript` lo pide para ligar plantilla y estilos. Tiene que ser el
 * mismo entre compilaciones del mismo archivo; la ruta alcanza.
 */
function identificar(ruta: string) {
	return Bun.hash(ruta).toString(16);
}

plugin({
	name: 'vue',
	setup(constructor) {
		constructor.onLoad({ filter: /\.vue$/ }, async ({ path }) => {
			const fuente = await Bun.file(path).text();
			const { descriptor } = parse(fuente, { filename: path });
			const id = identificar(path);
			const enTs = (descriptor.scriptSetup?.lang ?? descriptor.script?.lang) === 'ts';
			const complementos: 'typescript'[] = enTs ? ['typescript'] : [];
			const opcionesDePlantilla = {
				id,
				filename: path,
				compilerOptions: { expressionPlugins: complementos },
			};

			const partes: string[] = [];

			if (descriptor.scriptSetup || descriptor.script) {
				// Con `<script setup>` la plantilla se mete adentro del propio
				// `setup`, que es lo que hace Vite en producción: así las
				// variables del guión se resuelven como referencias directas y
				// no por el proxy del contexto de la instancia.
				const guion = compileScript(descriptor, {
					id,
					inlineTemplate: Boolean(descriptor.scriptSetup),
					templateOptions: opcionesDePlantilla,
				});
				partes.push(rewriteDefault(guion.content, '__sfc__', complementos));
			} else {
				partes.push('const __sfc__ = {};');
			}

			// Un componente sin `<script setup>` sí necesita su plantilla aparte.
			if (descriptor.template && !descriptor.scriptSetup) {
				const plantilla = compileTemplate({
					...opcionesDePlantilla,
					source: descriptor.template.content,
				});
				partes.push(plantilla.code, '__sfc__.render = render;');
			}

			// El nombre del archivo es lo que aparece en los avisos de Vue y en
			// el `wrapper.html()` de una prueba que falla.
			partes.push(`__sfc__.__file = ${JSON.stringify(path)};`, 'export default __sfc__;');

			return { contents: partes.join('\n'), loader: 'ts' };
		});
	},
});
