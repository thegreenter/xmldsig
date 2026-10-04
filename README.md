# XmlDSig - Greenter
[![Tests](https://github.com/thegreenter/xmldsig/actions/workflows/tests.yml/badge.svg)](https://github.com/thegreenter/xmldsig/actions/workflows/tests.yml)  

Esta libreria se emplea para firmar comprobantes electrónicos según las normas de SUNAT.

Se requiere el certificado en formato .PEM, puede utilizar el siguiente ejemplo para [convertir el certificado .PFX al otros formatos](https://github.com/thegreenter/xmldsig/blob/master/CONVERT.md).


## Instalar:

Empleando composer desde [packagist](https://packagist.org/packages/greenter/xmldsig).  

```bash
composer require greenter/xmldsig
```

## Ejemplo

```php

use Greenter\XMLSecLibs\Sunat\SignedXml;

require 'vendor/autoload.php';

$xmlPath = '20600995805-01-F001-1.xml';
$certPath = 'certifcate.pem'; // Antes convertir pfx -> pem (private+certificate keys) 

$signer = new SignedXml();
$signer->setCertificateFromFile($certPath);
// or $signer->setCertificate('-----BEGIN RSA PRIVATE KEY-----.....');

$xmlSigned = $signer->signFromFile($xmlPath);
// or $signer->signXml('<Invoice>....');

file_put_contents("signed.xml", $xmlSigned);
```

**Resultado:**  

Antes:
```xml
<ext:UBLExtensions>
    <ext:UBLExtension>
        <ext:ExtensionContent></ext:ExtensionContent>
    </ext:UBLExtension>
</ext:UBLExtensions>
```

Despues:
```xml
<ext:UBLExtensions>
    <ext:UBLExtension>
        <ext:ExtensionContent>
            <ds:Signature Id="SignIMM">
                <ds:SignedInfo>
                    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
                    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
                    <ds:Reference URI="">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                    <ds:DigestValue>IwJuNQGQaHmmm3iv2jj8JDv70Ow=</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>
                nLaghokzMNrmrfPnbIg9b........wzZ2CgLTVjWQUAQ4wDAYDVQQIEwVNYWluZTE1UiLFwZXXXPUlf2o=
                </ds:SignatureValue>
                <ds:KeyInfo>
                    <ds:X509Data>
                        <ds:X509Certificate>
                        MIIFhzCCA3OgAwI......MIIEVDCCAzygAwIBAgIJAPTrkMJbCOr1MA0GCSqGSIb3DQEBBQUAMHkxCzAJBgNVBAYTAlVTVQQIEwVNYWluZTEgMOiRJ00nE=
                        </ds:X509Certificate>
                    </ds:X509Data>
                </ds:KeyInfo>
            </ds:Signature>
        </ext:ExtensionContent>
    </ext:UBLExtension>
</ext:UBLExtensions>
```

### Algoritmo de firma

Por defecto se firma con RSA y SHA-1. Para firmar con RSA-SHA256 y digest SHA-256, configura los dos: con solo la firma en SHA-256, el documento se sigue resumiendo con SHA-1.

```php
use Greenter\XMLSecLibs\Sunat\SignedXml;
use Greenter\XMLSecLibs\XMLSecurityDSig;
use Greenter\XMLSecLibs\XMLSecurityKey;

$signer = new SignedXml();
$signer->setSignatureAlgorithm(XMLSecurityKey::RSA_SHA256);
$signer->setDigestAlgorithm(XMLSecurityDSig::SHA256);
```

`verifyXml()` toma el certificado y el algoritmo del XML verificado y los deja en la instancia: usa una instancia distinta para firmar y para verificar.
