# Auditoría de seguridad — greenter/xmldsig

Fecha: 2026-10-01 · Alcance: `src/`, `xmlseclibs.php`, `composer.json`, CI y archivos de prueba.
Tipo: revisión manual de código + pruebas de concepto (PHP 8.3). **Sin cambios de código.**

## Resumen

La librería es un fork (2017–2018) de [robrichards/xmlseclibs](https://github.com/robrichards/xmlseclibs) 3.0.x y no
incorpora los parches de seguridad que upstream publicó después (3.0.4 en adelante). Para el caso de uso principal
—**firmar** comprobantes SUNAT con el certificado propio— el riesgo es bajo. El riesgo real está en la
**verificación** de XML recibidos de terceros, donde la API actual no garantiza quién firmó el documento.

| # | Hallazgo | Severidad | Afecta a |
|---|----------|-----------|----------|
| 1 | `verifyXml()` confía en el certificado incrustado en el propio XML | **Alta** | Verificación |
| 2 | Múltiples `SignedInfo` aceptados (CVE-2019-3465 de upstream) | Media | Verificación (API de bajo nivel) |
| 3 | Búsqueda de referencias por `Id` sin rechazar duplicados (signature wrapping) | Media | Verificación (API de bajo nivel) |
| 4 | Algoritmos débiles por defecto y aceptados sin restricción (SHA-1, RIPEMD-160, DSA-SHA1, HMAC-SHA1) | Media | Firma y verificación |
| 5 | Confusión de algoritmo HMAC / comparación no constante | Media | Verificación (API de bajo nivel) |
| 6 | Transform XPath controlado por el documento (DoS) | Media | Verificación |
| 7 | Cifrado XML legado sin autenticación (AES-CBC, 3DES, RSA PKCS#1 v1.5) | Media | `XMLSecEnc` |
| 8 | Parseo XML sin endurecer ni validación de errores | Media/Baja | Firma y verificación |
| 9 | Plataforma desactualizada: `php >=5.5.9`, sin CI activo, sin dependencias de desarrollo | Baja | Mantenimiento |
| 10 | Deprecaciones PHP 8.4 (parámetros nullable implícitos) | Baja | Compatibilidad |
| 11 | `generateGUID()` no usa aleatoriedad criptográfica | Baja | Firma |
| 12 | Claves privadas de prueba versionadas | Informativo | Repositorio |
| 13 | Sin política de reporte de vulnerabilidades (`SECURITY.md`) | Informativo | Repositorio |

---

## 1. `verifyXml()` confía en el certificado del propio documento — Alta

**Dónde:** `src/Sunat/SignedXml.php:80-86` (`verifyXml`), `:241-260` (`setPublicKeyFromNode`), `:179-191` (`verify`).

`verifyXml()` extrae el `X509Certificate` del `KeyInfo` del XML y verifica la firma con esa misma clave. No compara
el certificado con uno de confianza, ni valida la cadena (CA), vigencia, uso de clave o revocación.

**Prueba de concepto (ejecutada):** se generó un certificado autofirmado nuevo (`CN=Atacante`), se firmó
`tests/invoice.xml` y luego se verificó con una instancia nueva de `SignedXml`:

```
PoC1 cert autofirmado verifyXml: true
```

Es decir, `true` sólo significa "el documento no fue alterado después de firmarse con *alguna* clave",
**no** "lo firmó el emisor esperado". Cualquiera puede modificar un comprobante y volver a firmarlo.

**Recomendación:**
- Documentado en el README (sección *Seguridad*).
- Si se verifican XML de terceros: obtener el certificado con `getPublicKey($doc)` y, antes de confiar, compararlo
  con el certificado esperado (huella SHA-256 con `openssl_x509_fingerprint($cert, 'sha256')`), o validar la cadena
  contra la CA (`openssl_x509_checkpurpose` / `openssl_x509_verify`) y las fechas `validFrom`/`validTo`; además,
  comprobar que el RUC del certificado coincide con el emisor del comprobante.
- A futuro: ofrecer en la API un "certificado/CA de confianza" opcional que haga esta validación.

## 2. Múltiples `SignedInfo` aceptados (CVE-2019-3465) — Media

**Dónde:** `src/XMLSecurityDSig.php:258-266` (`canonicalizeSignedInfo`), `:537` (`validateReference`), `:513` (`getRefIDs`).

Se canonicaliza (y por tanto se verifica criptográficamente) sólo el **primer** `SignedInfo`, pero
`validateReference()` y `getRefIDs()` recorren `./SignedInfo/Reference` de **todos** los `SignedInfo`. Un atacante
puede añadir un segundo `SignedInfo` no firmado con referencias propias, que acabarían en `getValidatedNodes()`.
Es la misma vulnerabilidad que upstream corrigió en xmlseclibs 3.0.4 (CVE-2019-3465): rechazar más de un `SignedInfo`
y usar `SignedInfo[1]`.

**Explotabilidad en el flujo SUNAT:** se probó inyectar un segundo `SignedInfo` que referencia un `ds:Object`
dentro de la firma; la verificación falló (`Reference validation failed`) porque `validateReference()` separa el
nodo `Signature` del documento antes de resolver IDs, y la firma SUNAT usa `URI=""` (documento completo). Por eso el
impacto en `SignedXml` es bajo, pero sí aplica a quien use `XMLSecurityDSig` directamente con referencias por `Id`
y confíe en `getValidatedNodes()`.

**Recomendación:** portar el parche de upstream (lanzar excepción si `count(SignedInfo) > 1`, consultar
`./secdsig:SignedInfo[1]/secdsig:Reference`).

## 3. Signature wrapping por IDs duplicados — Media

**Dónde:** `src/XMLSecurityDSig.php:449-457` (`processRefNode`).

La referencia `#id` se resuelve con `//*[@Id="…"]` y se toma `item(0)` sin comprobar que haya un único nodo con
ese ID. Si el consumidor luego lee un nodo distinto (p. ej. el segundo con el mismo `Id`, o por posición), puede
procesar datos no firmados (ataque clásico XSW).

**Recomendación:** rechazar la referencia si la consulta devuelve 0 o más de 1 nodo; que los consumidores sólo usen
los nodos devueltos por `getValidatedNodes()`.

## 4. Algoritmos débiles — Media

**Dónde:** `src/Sunat/SignedXml.php:39,48` (defaults RSA-SHA1 / SHA1, sin setters); `src/XMLSecurityDSig.php:282-297`
(digests aceptados: SHA1, SHA256/384/512, RIPEMD160); `src/XMLSecurityKey.php` (DSA-SHA1, HMAC-SHA1, RSA-SHA1);
`src/XMLSecurityDSig.php:713-728` (`locateKey` usa el algoritmo que dice el documento).

SHA-1 está desaconsejado para firmas (NIST SP 800-131A rev.2, colisiones prácticas desde 2017/2020). En verificación
el algoritmo lo elige el documento, sin lista blanca.

**Recomendación:** mantener RSA-SHA1 sólo si la normativa SUNAT vigente lo exige, pero exponer setters para
`keyAlgorithm`/`digestAlgorithm`/`canonicalMethod` y permitir RSA-SHA256; en verificación aplicar una lista blanca
configurable (p. ej. sólo RSA-SHA1/RSA-SHA256 y C14N) y rechazar DSA, HMAC y RIPEMD-160.

## 5. Confusión de algoritmo HMAC / comparación no constante — Media

**Dónde:** `src/XMLSecurityDSig.php:713-728`, `src/XMLSecurityKey.php:577-581`.

Si el documento declara `hmac-sha1`, `locateKey()` crea una clave HMAC; si se carga con material público (el
certificado), un atacante puede calcular la "firma". En `SignedXml::verify` está **mitigado** porque se exige
`1 !== $objXMLSecDSig->verify(...)` y HMAC devuelve `bool`, pero la API de bajo nivel queda expuesta.
Además la comparación HMAC usa `strcmp` (no tiempo-constante).

**Recomendación:** usar `hash_equals()`; impedir HMAC cuando la clave es pública/certificado; lista blanca (punto 4).

## 6. Transform XPath controlado por el documento — Media

**Dónde:** `src/XMLSecurityDSig.php:392-397` (`processTransforms`).

La expresión XPath del `Transform` se concatena tal cual y se ejecuta durante la canonicalización. Un documento
malicioso puede incluir expresiones muy costosas (DoS de CPU/memoria). También se aceptan transformaciones
desconocidas en silencio.

**Recomendación:** para SUNAT basta con `enveloped-signature` + C14N; rechazar cualquier otro transform en
verificación (o al menos hacerlo configurable).

## 7. Cifrado XML legado — Media

**Dónde:** `src/XMLSecurityKey.php` (AES-128/192/256-CBC, 3DES-CBC, RSA-1_5), `src/XMLSecEnc.php`.

Los modos CBC sin autenticación son vulnerables a padding/format oracle sobre XML Encryption
(Jager & Somorovsky, 2011) y RSA PKCS#1 v1.5 a Bleichenbacher. No hay AES-GCM (upstream lo añadió en 3.1.x).
No lo usa el flujo de firma SUNAT, pero la clase es pública.

**Recomendación:** soportar AES-GCM y RSA-OAEP, marcar CBC/3DES/RSA-1_5 como obsoletos, o retirar `XMLSecEnc` si no
se usa.

## 8. Parseo XML sin endurecer — Media/Baja

**Dónde:** `src/Sunat/SignedXml.php:289-295` (`getDocXml`), `src/XMLSecEnc.php:231`.

`loadXML()` se llama sin `LIBXML_NONET`, sin rechazar `DOCTYPE` y sin revisar el valor de retorno: un XML inválido
sólo emite un *warning* y continúa con un documento vacío (comprobado: termina en
`UnexpectedValueException: Signature DOM element not found.` en lugar de un error de parseo claro). En PHP ≥ 8.0 con
libxml ≥ 2.9 las entidades externas están desactivadas por defecto, pero `composer.json` declara `php >=5.5.9`, donde
XXE y *billion laughs* sí son posibles.

**Recomendación:** `loadXML($content, LIBXML_NONET)`, rechazar documentos con `$doc->doctype !== null`, y lanzar
excepción si `loadXML` devuelve `false` (usando `libxml_use_internal_errors(true)`).

## 9. Plataforma y mantenimiento — Baja

- `composer.json`: `"php": ">=5.5.9"`. PHP 5.x/7.x están fuera de soporte (sin parches de seguridad). Versiones con
  soporte a la fecha: 8.2+ (8.1 terminó su soporte de seguridad el 31-12-2025).
- CI: `.travis.yml` (PHP 5.6/7.2) — travis-ci.org está cerrado, por lo que no hay CI ejecutándose. Los badges del
  README apuntan a servicios inactivos.
- No hay `require-dev` (phpunit) ni `composer audit`/análisis estático.

**Recomendación:** subir a `php >=8.1` (versión mayor), GitHub Actions con matriz 8.1–8.4, `composer audit`, PHPStan.

## 10. Deprecaciones PHP 8.4 — Baja

Parámetros con tipo y `= null` sin `?` (p. ej. `SignedXml::getPublicKey(DOMDocument $doc = null)` en
`src/Sunat/SignedXml.php:113`) generan *deprecations* en PHP 8.4 y fallarán en PHP 9.

## 11. `generateGUID()` — Baja

`src/XMLSecurityDSig.php:112`: `md5(uniqid(mt_rand(), true))`. No es un secreto, pero se recomienda
`bin2hex(random_bytes(16))`.

## 12. Claves de prueba en el repositorio — Informativo

`tests/privkey.pem`, `tests/mycert.pem`, `tests/SFSCert.pfx`. Confirmar que son exclusivamente de prueba y que no
corresponden a ningún RUC/certificado real.

## 13. Política de seguridad — Informativo

No existe `SECURITY.md`. Recomendado indicar cómo reportar vulnerabilidades de forma privada
(GitHub Security Advisories).

---

## Prioridad sugerida

1. Advertir/validar el certificado en verificación (1) — ya documentado en el README.
2. Portar parches de upstream (2, 3, 5) y lista blanca de algoritmos/transforms (4, 6).
3. Endurecer parseo XML (8).
4. Versión mayor: PHP ≥ 8.1, CI en GitHub Actions, deprecaciones 8.4 (9, 10).

---

## Estado de las correcciones (2026-10-09)

| # | Estado |
|---|--------|
| 1 | Mitigado: `verifyXml()`/`verify()` usan el certificado configurado si existe y ya no reemplazan el certificado ni el algoritmo de la instancia; `getPublicKey($doc)` devuelve el certificado incrustado sin modificar la instancia. Sin certificado configurado sigue siendo sólo integridad (documentado en el README). Pendiente: validación de cadena/CA en la API. |
| 2 | Corregido: parche de upstream 3.0.4 (CVE-2019-3465). |
| 3 | Corregido: referencias externas, sin resolver o con `Id` duplicado se rechazan. |
| 4 | Corregido: setters de firma/digest/canonicalización en `SignedXml` y lista blanca en verificación (RSA-SHA1/RSA-SHA256, SHA-1/SHA-256, enveloped + C14N); listas configurables en `XMLSecurityDSig`. RSA-SHA1 se mantiene por defecto para firmar. |
| 5 | Corregido: `hash_equals()`, clave HMAC no admite material asimétrico y `verify()` exige que el algoritmo de la clave coincida con `SignatureMethod`. |
| 6 | Corregido: transform XPath rechazado en verificación por defecto; transforms y canonicalizaciones desconocidas rechazadas. |
| 7 | Mitigado: AES-GCM y RSA-OAEP (upstream 3.1.x), validación de padding CBC, CBC/3DES/RSA-1_5 marcados como obsoletos. |
| 8 | Corregido: `LIBXML_NONET`, rechazo de `DOCTYPE` y excepción clara en XML inválido. |
| 9 | Corregido: `php >=8.1`, GitHub Actions 8.1–8.4, PHPUnit 10, `composer audit`, PHPStan. |
| 10 | Corregido. |
| 11 | Corregido: `random_bytes()`. |
| 12 | Revisado: `mycert.pem`/`privkey.pem`/`certificate.pem` son los de prueba de xmlseclibs; `SFSCert.pfx` es autofirmado (certificado de prueba del SFS de SUNAT). |
| 13 | Corregido: `SECURITY.md`. |
