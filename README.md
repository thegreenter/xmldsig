# XmlDSig - Facturación Electrónica (SUNAT-PE)
[![Travis-CI](https://travis-ci.org/giansalex/xmldsig.svg?branch=master)](https://travis-ci.org/giansalex/xmldsig)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/bebcd8e55eac4e409525b2d7fb98f269)](https://www.codacy.com/app/giansalex/xmldsig?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=giansalex/xmldsig&amp;utm_campaign=Badge_Grade)

Esta libreria se emplea para firmar documentos electronicos segun las normas de SUNAT.

Se requiere convertir el certificado .PFX a .PEM, aqui una herramienta online para convertirlo:  
https://www.sslshopper.com/ssl-converter.html

## Install:

Install using Composer from [packagist](https://packagist.org/packages/giansalex/xmldsig).  

```bash
composer require giansalex/xmldsig
```

## Ejemplo
```php

use Greenter\XMLSecLibs\Sunat\SunatXmlSecAdapter;

require 'vendor/autoload.php';

$xmlPath = 'path-dir/20600995805-01-F001-1.xml';
$certPath = 'path-dir/SFSCert.pem'; // Convertir pfx to pem 

$xmlDocument = new DOMDocument();
$xmlDocument->load($xmlPath);

$xmlTool = new SunatXmlSecAdapter();
$xmlTool->setPrivateKey(file_get_contents($certPath));
$xmlTool->setPublicKey(file_get_contents($certPath));

$xmlTool->sign($xmlDocument);

header('Content-Type: text/xml');
echo $xmlDocument->saveXML();
```

**Resultado:**  

Before:
```xml
<ext:UBLExtensions>
    <ext:UBLExtension>
        <ext:ExtensionContent></ext:ExtensionContent>
    </ext:UBLExtension>
</ext:UBLExtensions>
```

After:
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
