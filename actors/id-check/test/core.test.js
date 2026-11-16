import test from 'node:test';
import assert from 'node:assert/strict';
import { validateIban, validateBic, validateSiren, validateSiret, validateVat, detectType, validateItem, summarize, luhn, frVatKey } from '../src/core.js';

// Vectors computed independently in Python (IBAN mod 97, Luhn, FR VAT key formula).
test('IBAN: valid examples from several countries', () => {
  for (const i of ['FR1420041010050500013M02606', 'DE89 3704 0044 0532 0130 00', 'GB82WEST12345698765432', 'NL91ABNA0417164300',
    'ES9121000418450200051332', 'IT60X0542811101000000123456', 'BE68539007547034', 'CH9300762011623852957']) {
    assert.equal(validateIban(i).verdict, 'ALLOW', i);
  }
});
test('IBAN: bad checksum, bad length, bad structure', () => {
  assert.equal(validateIban('DE89370400440532013001').verdict, 'BLOCK');
  assert.match(validateIban('DE8937040044053201300').reasons[0], /Wrong length/);
  assert.equal(validateIban('1234').verdict, 'BLOCK');
});
test('BIC format', () => {
  assert.equal(validateBic('BNPAFRPP').verdict, 'REVIEW');
  assert.equal(validateBic('BNPAFRPPXXX').details.branch, 'XXX');
  assert.equal(validateBic('BNP123').verdict, 'BLOCK');
});
test('SIREN / SIRET Luhn', () => {
  assert.equal(validateSiren('732 829 320').verdict, 'ALLOW');
  assert.equal(validateSiren('123456789').verdict, 'BLOCK');
  assert.equal(validateSiret('73282932000074').verdict, 'ALLOW');
  assert.equal(validateSiret('55208131700049').verdict, 'BLOCK');
  assert.equal(validateSiret('7328293200007').verdict, 'BLOCK');
});
test('La Poste SIRET rule', () => {
  let nic;
  for (let i = 0; i < 100000; i++) {
    const s = '356000000' + String(i).padStart(5, '0');
    if (!luhn(s) && [...s].reduce((a, c) => a + +c, 0) % 5 === 0) { nic = s; break; }
  }
  assert.ok(nic);
  assert.equal(validateSiret(nic).verdict, 'ALLOW');
});
test('French VAT key', () => {
  assert.equal(frVatKey('732829320'), '44');
  assert.equal(validateVat('FR44732829320').verdict, 'ALLOW');
  assert.equal(validateVat('FR 03 552 081 317').verdict, 'ALLOW');
  assert.equal(validateVat('FR45732829320').verdict, 'BLOCK');
  assert.equal(validateVat('FR44123456789').verdict, 'BLOCK');
});
test('Other EU VAT: format-only => REVIEW', () => {
  assert.equal(validateVat('DE123456789').verdict, 'REVIEW');
  assert.equal(validateVat('NL123456789B01').verdict, 'REVIEW');
  assert.equal(validateVat('DE12345').verdict, 'BLOCK');
  assert.equal(validateVat('ZZ123456789').verdict, 'BLOCK');
});
test('auto-detection and batch verdict', () => {
  assert.equal(detectType('FR1420041010050500013M02606'), 'iban');
  assert.equal(detectType('73282932000074'), 'siret');
  assert.equal(detectType('732829320'), 'siren');
  assert.equal(detectType('FR44732829320'), 'vat');
  assert.equal(detectType('BNPAFRPP'), 'bic');
  assert.equal(detectType('hello'), null);
  const rs = ['NL91ABNA0417164300', 'DE89370400440532013001'].map((x) => validateItem(x));
  assert.equal(summarize(rs).verdict, 'BLOCK');
  assert.equal(summarize([validateItem('732829320')]).verdict, 'ALLOW');
  assert.equal(validateItem({ value: 'BNPAFRPP', type: 'bic' }).verdict, 'REVIEW');
});
