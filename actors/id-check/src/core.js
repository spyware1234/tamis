
const IBAN_LENGTHS = {
  AD: 24, AE: 23, AL: 28, AT: 20, AZ: 28, BA: 20, BE: 16,
  BG: 22, BH: 22, BR: 29, BY: 28, CH: 21, CR: 22, CY: 28,
  CZ: 24, DE: 22, DK: 18, DO: 28, EE: 20, ES: 24, FI: 18,
  FO: 18, FR: 27, GB: 22, GE: 22, GI: 23, GL: 18, GR: 27,
  GT: 28, HR: 21, HU: 28, IE: 22, IL: 23, IQ: 23, IS: 26,
  IT: 27, JO: 30, KW: 30, KZ: 20, LB: 28, LC: 32, LI: 21,
  LT: 20, LU: 20, LV: 21, MC: 27, MD: 24, ME: 22, MK: 19,
  MR: 27, MT: 31, MU: 30, NL: 18, NO: 15, PK: 24, PL: 28,
  PS: 29, PT: 25, QA: 29, RO: 24, RS: 22, SA: 24, SC: 31,
  SE: 24, SI: 19, SK: 24, SM: 27, ST: 25, SV: 28, TL: 23,
  TN: 24, TR: 26, UA: 29, VA: 22, VG: 24, XK: 20
};

const PUBLIC_TYPES = new Set(['SIREN', 'SIRET', 'VAT', 'BIC']);
const LA_POSTE_SIREN = '356000000';

export function normalize(raw) {
  return String(raw ?? '')
    .replace(/[\s._/-]/g, '')
    .toUpperCase();
}

function mod97(value) {
  let remainder = 0;
  for (const char of value) {
    const expanded = /[A-Z]/.test(char)
      ? String(char.charCodeAt(0) - 55)
      : char;
    for (const digit of expanded) {
      remainder = (remainder * 10 + Number(digit)) % 97;
    }
  }
  return remainder;
}

function luhn(value) {
  let sum = 0;
  let doubleDigit = false;

  for (let i = value.length - 1; i >= 0; i--) {
    let digit = Number(value[i]);

    if (doubleDigit) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }

    sum += digit;
    doubleDigit = !doubleDigit;
  }

  return sum % 10 === 0;
}

function digitSum(value) {
  return [...value].reduce((sum, digit) => sum + Number(digit), 0);
}

function result(type, verdict, reasons = [], details = {}) {
  return {
    type,
    verdict,
    valid: verdict === 'ALLOW',
    reasons,
    details
  };
}

export function validateIban(value) {
  const iban = normalize(value);

  if (!/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(iban)) {
    return result('IBAN', 'BLOCK', ['Invalid IBAN format']);
  }

  const country = iban.slice(0, 2);
  const expectedLength = IBAN_LENGTHS[country];

  if (!expectedLength) {
    return result('IBAN', 'REVIEW', ['Unknown country IBAN length']);
  }

  if (iban.length !== expectedLength) {
    return result('IBAN', 'BLOCK', ['Invalid IBAN length'], {
      expectedLength,
      actualLength: iban.length
    });
  }

  const rearranged = iban.slice(4) + iban.slice(0, 4);

  if (mod97(rearranged) !== 1) {
    return result('IBAN', 'BLOCK', ['IBAN checksum failed']);
  }

  return result('IBAN', 'ALLOW', [], {
    country,
    checksumValid: true
  });
}

export function validateBic(value) {
  const bic = normalize(value);

  if (!/^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$/.test(bic)) {
    return result('BIC', 'BLOCK', ['Invalid BIC format']);
  }

  return result('BIC', 'REVIEW', [
    'BIC format looks valid, but existence cannot be verified offline'
  ]);
}

export function validateSiren(value) {
  const siren = normalize(value);

  if (!/^\d{9}$/.test(siren)) {
    return result('SIREN', 'BLOCK', ['SIREN must contain exactly 9 digits']);
  }

  if (/^0+$/.test(siren)) {
    return result('SIREN', 'BLOCK', ['SIREN cannot contain only zeros']);
  }

  if (siren === LA_POSTE_SIREN) {
    return result('SIREN', 'ALLOW', [], {
      checksumValid: true,
      specialCase: 'La Poste'
    });
  }

  if (!luhn(siren)) {
    return result('SIREN', 'BLOCK', ['SIREN Luhn checksum failed']);
  }

  return result('SIREN', 'ALLOW', [], {
    checksumValid: true
  });
}

export function validateSiret(value) {
  const siret = normalize(value);

  if (!/^\d{14}$/.test(siret)) {
    return result('SIRET', 'BLOCK', ['SIRET must contain exactly 14 digits']);
  }

  const siren = siret.slice(0, 9);

  if (/^0+$/.test(siren)) {
    return result('SIRET', 'BLOCK', ['SIREN part cannot contain only zeros']);
  }

  // La Poste uses a special checksum rule.
  if (siren === LA_POSTE_SIREN) {
    const valid = luhn(siret) || digitSum(siret) % 5 === 0;

    if (!valid) {
      return result('SIRET', 'BLOCK', [
        'La Poste SIRET checksum failed'
      ]);
    }

    return result('SIRET', 'ALLOW', [], {
      siren,
      checksumValid: true,
      specialCase: 'La Poste'
    });
  }

  // Check the SIREN part independently.
  if (!luhn(siren)) {
    return result('SIRET', 'BLOCK', [
      'SIREN part Luhn checksum failed'
    ]);
  }

  // Then check the complete SIRET.
  if (!luhn(siret)) {
    return result('SIRET', 'BLOCK', [
      'SIRET Luhn checksum failed'
    ]);
  }

  return result('SIRET', 'ALLOW', [], {
    siren,
    checksumValid: true
  });
}

export function validateVat(value) {
  const vat = normalize(value);

  if (!/^[A-Z]{2}[A-Z0-9]{2,13}$/.test(vat)) {
    return result('VAT', 'BLOCK', ['Invalid VAT number format']);
  }

  const country = vat.slice(0, 2);
  const number = vat.slice(2);

  if (country === 'FR') {
    if (!/^[A-Z0-9]{2}\d{9}$/.test(number)) {
      return result('VAT', 'BLOCK', ['Invalid French VAT format']);
    }

    const key = number.slice(0, 2);
    const siren = number.slice(2);

    if (/^0+$/.test(siren)) {
      return result('VAT', 'BLOCK', ['SIREN part cannot contain only zeros']);
    }

    if (!luhn(siren)) {
      return result('VAT', 'BLOCK', ['French VAT SIREN checksum failed']);
    }

    const expectedKey = String(
      (12 + 3 * (Number(siren) % 97)) % 97
    ).padStart(2, '0');

    if (key !== expectedKey) {
      return result('VAT', 'BLOCK', ['French VAT key checksum failed']);
    }

    return result('VAT', 'ALLOW', [], {
      country,
      siren,
      checksumValid: true
    });
  }

  return result('VAT', 'REVIEW', [
    'Format looks plausible, but this country VAT number cannot be verified offline'
  ], {
    country
  });
}

export function detectType(value) {
  const normalized = normalize(value);

  if (/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(normalized)) return 'iban';
  if (/^\d{14}$/.test(normalized)) return 'siret';
  if (/^\d{9}$/.test(normalized)) return 'siren';
  if (/^[A-Z]{2}[A-Z0-9]{2,13}$/.test(normalized)) return 'vat';
  if (/^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$/.test(normalized)) return 'bic';

  return null;
}

export function validateItem(input, forcedType = 'auto') {
  let value = input;
  let type = forcedType;

  if (input && typeof input === 'object' && !Array.isArray(input)) {
    value = input.value;
    if (input.type) type = input.type;
  }

  if (typeof value !== 'string' && typeof value !== 'number') {
    return result('UNKNOWN', 'BLOCK', ['Input must be a string or number']);
  }

  const raw = String(value).trim();

  if (!raw || raw.length > 100) {
    return result('UNKNOWN', 'BLOCK', ['Input is empty or too long']);
  }

  const normalized = normalize(raw);

  if (type === 'auto') {
    type = detectType(normalized);
  }

  if (!type) {
    return result('UNKNOWN', 'REVIEW', ['Could not automatically detect identifier type']);
  }

  switch (type.toLowerCase()) {
    case 'iban':
      return validateIban(normalized);
    case 'bic':
      return validateBic(normalized);
    case 'siren':
      return validateSiren(normalized);
    case 'siret':
      return validateSiret(normalized);
    case 'vat':
      return validateVat(normalized);
    default:
      return result('UNKNOWN', 'BLOCK', ['Unsupported identifier type']);
  }
}

export function maskValue(value) {
  const text = String(value ?? '');

  if (text.length <= 8) return '*'.repeat(text.length);

  return `${text.slice(0, 4)}${'*'.repeat(text.length - 8)}${text.slice(-4)}`;
}

export function toOutput(validation, index, options = {}) {
  const maskSensitive = options.maskSensitive !== false;
  const rawInput = String(validation.input ?? '');
  const shouldMask = maskSensitive && validation.type === 'IBAN';

  return {
    index,
    input: shouldMask ? maskValue(rawInput) : rawInput,
    type: validation.type,
    normalized: shouldMask ? maskValue(validation.normalized ?? rawInput) : validation.normalized,
    verdict: validation.verdict,
    valid: validation.valid,
    reasons: validation.reasons,
    details: validation.details,
    masked: shouldMask
  };
}

export function summarize(results) {
  const counts = {
    ALLOW: 0,
    REVIEW: 0,
    BLOCK: 0
  };

  for (const item of results) {
    if (counts[item.verdict] !== undefined) {
      counts[item.verdict]++;
    }
  }

  return {
    verdict: counts.BLOCK ? 'BLOCK' : counts.REVIEW ? 'REVIEW' : 'ALLOW',
    processed: results.length,
    ...counts
  };
}
