import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const source = readFileSync('apps/web/legacy-admin.js', 'utf8');
const dispatcher = source.slice(source.indexOf('const adminActions ='));
const calls = [];
let click;
const context = {document: {addEventListener: (_, handler) => {click = handler;}}};
for (const name of dispatcher.match(/const adminActions = \{([^}]+)\}/)[1].split(',').map(x => x.trim())) {
  context[name] = (...args) => calls.push([name, ...args]);
}
vm.runInNewContext(dispatcher, context);
function invoke(action, backdrop = false) {
  const element = {dataset: {action}};
  const target = backdrop ? element : {};
  target.closest = () => element;
  click({target});
}
invoke("openDevice('test-device')");
invoke('removeGrant(\'test-device\',"user|example")');
invoke('copyText("safe;quoted \\"text\\" and apostrophe\'s")');
invoke('closeModal();refreshAll(true)');
invoke('closeOnBackdrop()');
invoke('closeOnBackdrop()', true);
const count = calls.length;
invoke('constructor("return process")');
invoke('logout();removeGrant("x","y")');
invoke('copyText(fetch("https://example.invalid"))');
assert.equal(calls.length, count);
assert.deepEqual(calls, [
  ['openDevice', 'test-device'], ['removeGrant', 'test-device', 'user|example'],
  ['copyText', 'safe;quoted "text" and apostrophe\'s'], ['closeModal'],
  ['refreshAll', true], ['closeModal'],
]);
for (const file of ['apps/web/legacy-admin.html', 'apps/web/legacy-admin.js']) {
  assert.doesNotMatch(readFileSync(file, 'utf8'), /\bonclick=|\bstyle="/);
}
console.log('PASS: CSP-compatible admin controls, escaped arguments and unauthorized action rejection');
