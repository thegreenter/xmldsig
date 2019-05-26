--TEST--
Check Sign xml with .pem certificate
--FILE--
<?php

use Greenter\XMLSecLibs\Sunat\SignedXml;

require __DIR__.'/../vendor/autoload.php';

$xmlPath = __DIR__ . '/invoice.xml';
$certPath = __DIR__ . '/certificate.pem'; // Convertir pfx to pem

$xmlDocument = new DOMDocument();
$xmlDocument->load($xmlPath);

$xmlTool = new SignedXml();
$xmlTool->setCertificateFromFile($certPath);

$xmlTool->sign($xmlDocument);

$content = $xmlDocument->saveXML();

$result = $xmlTool->verify($xmlDocument);

if ($result === true) {
    echo "OK\n";
}
?>
--EXPECTF--
OK