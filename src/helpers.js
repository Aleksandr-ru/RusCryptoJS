import DN from './DN';

const oids = [
  { oid: '1.2.643.3.131.1.1',    short: 'INN',    full: 'ИНН' },
  { oid: '1.2.643.100.1',        short: 'OGRN',   full: 'ОГРН' },
  { oid: '1.2.643.100.5',        short: 'OGRNIP', full: 'ОГРНИП' },
  { oid: '1.2.643.100.3',        short: 'SNILS',  full: 'СНИЛС' },
  { oid: '1.2.840.113549.1.9.1', short: 'E',      full: 'emailAddress' },
  { oid: '2.5.4.3',              short: 'CN',     full: 'commonName' },
  { oid: '2.5.4.4',              short: 'SN',     full: 'surname' },
  { oid: '2.5.4.42',             short: 'G',      full: 'givenName' },
  { oid: '2.5.4.6',              short: 'C',      full: 'countryName' },
  { oid: '2.5.4.7',              short: 'L',      full: 'localityName' },
  { oid: '2.5.4.8',              short: 'S',      full: 'stateOrProvinceName' },
  { oid: '2.5.4.9',              short: 'STREET', full: 'streetAddress' },
  { oid: '2.5.4.10',             short: 'O',      full: 'organizationName' },
  { oid: '2.5.4.11',             short: 'OU',     full: 'organizationalUnitName' },
  { oid: '2.5.4.12',             short: 'T',      full: 'title' },
//  { oid: '2.5.4.16',             short: '?',      full: 'postalAddress' },
];

/**
 * Перевод кирилицы в латиницу в ключах объекта с информацией о сертификате
 * @param {DN} dn 
 * @returns {DN}
 */
export function convertDN(dn) {
  const result = new DN;  
  for (const field of Object.keys(dn)) {
    const oid = oids.find(item => item.oid == field || item.full == field);
    if (oid) {
      result[oid.short] = dn[field];
    }
    else {
      result[field] = dn[field];
    }
  }
  return result;
}

/**
 * Убирает кавычки из строки DN
 * @param {string} str 
 */
export function stripDnQuotes(str) 
{
  return str.replace(/="/g, '=').replace(/",/g, ',');
}