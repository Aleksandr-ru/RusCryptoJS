export function convertInfoToLat(certInfo) {
  let result = {};
  let rus = ["ИНН", "КПП", "ОГРН", "ОГРНИП", "СНИЛС"];
  let en = ["INN", "KPP", "OGRN", "OGRNIP", "SNILS"];
  for (const field of Object.keys(certInfo)) {
    const index = rus.indexOf(field);
    if (index !== -1) {
      result[en[index]] = certInfo[field];
    } else {
      result[field] = certInfo[field];
    }
  }
  return result;
}
