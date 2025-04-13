import { writeFile } from 'node:fs/promises';
import packagejson from './package.json';

const finalPackageJson = { ...packagejson };

(finalPackageJson as any).version = process.env.REF_NAME ?? (packagejson as any).version ?? '0.0.1';

await writeFile('package.json', JSON.stringify(finalPackageJson), {
	encoding: 'utf-8'
});
