/**
 * Перевод кирилицы в латиницу в ключах объекта с информацией о сертификате
 * @param {DN} dn 
 * @returns {DN}
 */
export function convertDN(dn) {
  let result = {};
  let rus = ["ИНН", "КПП", "ОГРН", "ОГРНИП", "СНИЛС"];
  let en = ["INN", "KPP", "OGRN", "OGRNIP", "SNILS"];
  //TODO: convert "OID.1.2.3.4" to "1.2.3.4"
  for (const field of Object.keys(dn)) {
    const index = rus.indexOf(field);
    if (index > -1) {
      result[en[index]] = dn[field];
    } 
    else {
      result[field] = dn[field];
    }
  }
  return result;
}
