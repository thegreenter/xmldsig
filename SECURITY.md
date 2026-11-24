# Política de seguridad

## Versiones con soporte

| Versión | Soporte |
|---------|---------|
| Última versión mayor (PHP >= 8.1) | :white_check_mark: |
| Versiones anteriores (PHP 5.x / 7.x) | :x: |

## Reportar una vulnerabilidad

No abras un issue público. Reporta la vulnerabilidad de forma privada mediante
[GitHub Security Advisories](https://github.com/thegreenter/xmldsig/security/advisories/new)
indicando:

- versión afectada y versión de PHP,
- descripción del problema e impacto,
- pasos o XML de prueba para reproducirlo (sin certificados ni datos reales).

Responderemos lo antes posible y coordinaremos la publicación de la corrección.

## Alcance

Esta librería es un fork de [robrichards/xmlseclibs](https://github.com/robrichards/xmlseclibs). Las vulnerabilidades
de upstream que apliquen también se consideran dentro del alcance.

Los certificados y claves de `tests/` son exclusivamente de prueba (autofirmados) y no deben usarse en producción.
