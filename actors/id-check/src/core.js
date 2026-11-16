
// Pure validation logic: no dependencies, no network.
// Verdicts: ALLOW | REVIEW | BLOCK.
// ALLOW = passes an offline checksum/length test.
// REVIEW = format looks right but cannot be fully verified offline.
// BLOCK = fails validation.

const IBAN_LENGTHS = {
  AD: 24, AE: 23, AL: 28, AT: 20, AZ: 28, BA: 20, BE: 16, BG: 22, BH: 22, BR: 29, BY: 28, CH: 21, CR: 22, CY: 28,
  CZ: 24, DE: 22, DK: 18, DO: 28, EE: 20, EG: 29, ES: 24, FI: 18, FO: 18, FR: 27, GB: 22, GE: 22, GI: 23, GL: 18,
  GR: 27, GT: 28, HR: 21, HU: 28, IE: 22, IL: 23, IQ: 23, IS: 26, IT: 27, JO: 30, KW: 30, KZ: 20, LB: 28, LI: 21,
  LT: 20, LU: 20, LV: 21, MC: 27, MD: 24, ME: 22, MK: 19, MR: 27, MT: 31, MU: 30, NL: 18, NO: 15, PK: 24, PL: 28,
  PS: 29, PT: 25, QA: 29, RO: 24, RS: 22, SA: 24, SE: 24, SI: 19, SK: 24, SM: 27, TL: 23, TN: 24, TR: 26, UA: 29,
  VA: 22, VG: 24, XK: 20,
};

const VAT_FORMATS = {
  AT: /^U\d{8}$/, BE: /^[01]\d{9}$/, BG: /^\d{9,10}$/, CY: /^\d{8}[A-Z]$/, CZ: /^\d{8,10}$/, DE: /^\d{9}$/,
  DK: /^\d{8}$/, EE: /^\d{9}$/, EL: /^\d{9}$/, ES: /^[A-Z0-9]\d{7}[A-Z0-9]$/, FI: /^\d{8}$/, FR: /^[A-Z0-9]{2}\d{9}$/,
  HR: /^\d{11}$/, HU: /^\d{8}$/, IE: /^(\d{7}[A-Z]{1,2}|\d[A-Z+*]\d{5}[A-Z])$/, IT: /^\d{11}$/,
  LT: /^(\d{9}|\d{12})$/, LU: /^\d{8}$/, LV: /^\d{11}$/, MT: /^\d{8}$/, NL: /^\d{9}B\d{2}$/, PL: /^\d{10}$/,
  PT: /^\d{9}$/, RO: /^\d{2,10}$/, SE: /^\d{12}$/, SI: /^\d{8}$/, SK: /^\d{10}$/,
  GB: /^(\d{9}|\d{12}|GD\d{3}|HA\d{3})$/, XI: /^(\d{9}|\d{12}|GD\d{3}|HA\d{3})$/,
};

export const normalize = (raw) =>
  String(raw ?? '').replace(/[\s.\\\-_/]/g, '').toUpperCase();

const result = (verdict, type, normalized, reasons, details = {}) => ({
  type,
  normalized,
  verdict,
  valid: verdict === 'ALLOW',
  reasons,
  details,
});

function mod97(str) {
  let r = 0;

  for (const ch of str) {
    const v = ch >= 'A' ? ch.charCodeAt(0) - 55 : ch.charCodeAt(0) - 48;
    r = (v > 9 ? r * 100 + v : r * 10 + v) % 97;
  }

  return r;
}

export function luhn(digits) {
  let sum = 0;

  for (let i = 0; i < digits.length; i++) {
    let d = digits.charCodeAt(digits.length - 1 - i) - 48;

    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }

    sum += d;
  }

  return sum % 10 === 0;
}

// Reject identifiers made entirely of zeros.
const isAllZeros = (value) => /^0+$/.test(value);

export function validateIban(raw) {
  const n = normalize(raw);

  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(n)) {
    return result('BLOCK', 'iban', n, ['Invalid IBAN structure']);
  }

  const cc = n.slice(0, 2);
  const expected = IBAN_LENGTHS[cc];

  if (expected && n.length !== expected) {
    return result(
      'BLOCK',
      'iban',
      n,
      [`Wrong length for ${cc}: expected ${expected}, got ${n.length}`],
      { country: cc }
    );
  }

  if (mod97(n.slice(4) + n.slice(0, 4)) !== 1) {
    return result('BLOCK', 'iban', n, ['Checksum (mod 97) failed'], { country: cc });
  }

  if (!expected) {
    return result(
      'REVIEW',
      'iban',
      n,
      ['Checksum OK but country length rule not in table'],
      { country: cc }
    );
  }

  return result('ALLOW', 'iban', n, [], { country: cc });
}

export function validateBic(raw) {
  const n = normalize(raw);

  if (!/^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$/.test(n)) {
    return result('BLOCK', 'bic', n, ['Invalid BIC format (8 or 11 characters)']);
  }

  return result(
    'REVIEW',
    'bic',
    n,
    ['Format OK; BIC has no checksum, existence cannot be verified offline'],
    {
      bankCode: n.slice(0, 4),
      country: n.slice(4, 6),
      location: n.slice(6, 8),
      branch: n.slice(8) || null,
    }
  );
}

const LA_POSTE_SIREN = '356000000';
const digitSum = (s) =>
  [...s].reduce((a, c) => a + (c.charCodeAt(0) - 48), 0);

export function validateSiren(raw) {
  const n = normalize(raw);

  if (!/^\d{9}$/.test(n)) {
    return result('BLOCK', 'siren', n, ['SIREN must be 9 digits']);
  }

  if (isAllZeros(n)) {
    return result('BLOCK', 'siren', n, ['SIREN cannot be all zeros']);
  }

  if (!luhn(n)) {
    return result('BLOCK', 'siren', n, ['Luhn checksum failed']);
  }

  return result('ALLOW', 'siren', n, []);
}

export function validateSiret(raw) {
  const n = normalize(raw);

  if (!/^\d{14}$/.test(n)) {
    return result('BLOCK', 'siret', n, ['SIRET must be 14 digits']);
  }

  const siren = n.slice(0, 9);

  if (isAllZeros(siren)) {
    return result(
      'BLOCK',
      'siret',
      n,
      ['SIRET cannot contain an all-zero SIREN']
    );
  }

  const ok =
    siren === LA_POSTE_SIREN
      ? (luhn(n) || digitSum(n) % 5 === 0)
      : luhn(n);

  if (!ok) {
    return result('BLOCK', 'siret', n, ['Luhn checksum failed']);
  }

  return result('ALLOW', 'siret', n, [], {
    siren,
    nic: n.slice(9),
  });
}

export const frVatKey = (siren) =>
  String((12 + 3 * (Number(siren) % 97)) % 97).padStart(2, '0');

export function validateVat(raw) {
  const n = normalize(raw);
  const cc = n.slice(0, 2);
  const body = n.slice(2);
  const fmt = VAT_FORMATS[cc];

  if (!fmt) {
    return result('BLOCK', 'vat', n, [
      `Unknown or unsupported VAT country prefix "${cc}"`,
    ]);
  }

  if (!fmt.test(body)) {
    return result('BLOCK', 'vat', n, [`Invalid ${cc} VAT number format`], {
      country: cc,
    });
  }

  if (cc === 'FR') {
    const key = body.slice(0, 2);
    const siren = body.slice(2);

    if (isAllZeros(siren)) {
      return result(
        'BLOCK',
        'vat',
        n,
        ['French VAT number cannot contain an all-zero SIREN'],
        { country: cc, siren }
      );
    }

    if (!luhn(siren)) {
      return result(
        'BLOCK',
        'vat',
        n,
        ['Embedded SIREN fails Luhn checksum'],
        { country: cc, siren }
      );
    }

    if (/^\d{2}$/.test(key)) {
      if (key !== frVatKey(siren)) {
        return result(
          'BLOCK',
          'vat',
          n,
          [`French VAT key mismatch (expected ${frVatKey(siren)})`],
          { country: cc, siren }
        );
      }

      return result('ALLOW', 'vat', n, [], { country: cc, siren });
    }

    return result(
      'REVIEW',
      'vat',
      n,
      ['Alphanumeric French VAT key cannot be verified offline'],
      { country: cc, siren }
    );
  }

  return result(
    'REVIEW',
    'vat',
    n,
    ['Format OK; no offline checksum implemented for this country. Confirm existence with VIES'],
    { country: cc }
  );
}

export function detectType(raw) {
  const n = normalize(raw);

  if (
    /^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(n) &&
    (IBAN_LENGTHS[n.slice(0, 2)] === n.length || !VAT_FORMATS[n.slice(0, 2)])
  ) {
    return 'iban';
  }

  if (/^\d{14}$/.test(n)) return 'siret';
  if (/^\d{9}$/.test(n)) return 'siren';

  if (
    VAT_FORMATS[n.slice(0, 2)] &&
    /^[A-Z]{2}[A-Z0-9+*]{2,12}$/.test(n) &&
    /\d/.test(n)
  ) {
    return 'vat';
  }

  if (/^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$/.test(n)) {
    return 'bic';
  }

  return null;
}

const VALIDATORS = {
  iban: validateIban,
  bic: validateBic,
  siren: validateSiren,
  siret: validateSiret,
  vat: validateVat,
};

const MAX_ITEM_LENGTH = 100;

export function validateItem(input, forcedType = 'auto') {
  const obj =
    typeof input === 'object' && input !== null && !Array.isArray(input);

  const value = obj ? input.value : input;
  const hint = obj && input.type ? input.type : forcedType;

  if (typeof value !== 'string' && typeof value !== 'number') {
    return {
      input: null,
      ...result('BLOCK', 'unknown', '', [
        'Each item must be a string (or an object with a "value" string)',
      ]),
    };
  }

  const text = String(value);

  if (text.length > MAX_ITEM_LENGTH) {
    return {
      input: null,
      ...result('BLOCK', 'unknown', '', [
        `Item longer than ${MAX_ITEM_LENGTH} characters`,
      ]),
    };
  }

  if (hint && hint !== 'auto' && !VALIDATORS[hint]) {
    return {
      input: text,
      ...result('BLOCK', 'unknown', normalize(text), [
        `Unsupported type "${String(hint).slice(0, 20)}"`,
      ]),
    };
  }

  const type = hint && hint !== 'auto' ? hint : detectType(text);

  if (!type) {
    return {
      input: text,
      ...result('BLOCK', 'unknown', normalize(text), [
        'Could not recognise the identifier type',
      ]),
    };
  }

  return {
    input: text,
    ...VALIDATORS[type](text),
  };
}

// Privacy: IBANs and unrecognised identifiers are masked by default.
export function maskValue(value) {
  const n = normalize(value);

  if (n.length <= 8) return '*'.repeat(n.length);

  return n.slice(0, 4) + '*'.repeat(n.length - 8) + n.slice(-4);
}

const PUBLIC_TYPES = new Set(['siren', 'siret', 'vat', 'bic']);

export function toOutput(r, index, { maskSensitive = true } = {}) {
  const out = {
    index,
    input: r.input,
    type: r.type,
    normalized: r.normalized,
    verdict: r.verdict,
    valid: r.valid,
    reasons: r.reasons,
    details: r.details,
    masked: false,
  };

  if (maskSensitive && !PUBLIC_TYPES.has(r.type)) {
    out.input = r.input == null ? null : maskValue(r.input);
    out.normalized = maskValue(r.normalized);
    out.masked = true;
  }

  return out;
}

export function summarize(results) {
  const counts = { ALLOW: 0, REVIEW: 0, BLOCK: 0 };

  for (const r of results) {
    counts[r.verdict]++;
  }

  const verdict = counts.BLOCK
    ? 'BLOCK'
    : counts.REVIEW
      ? 'REVIEW'
      : 'ALLOW';

  return {
    verdict,
    total: results.length,
    ...counts,
  };
}
