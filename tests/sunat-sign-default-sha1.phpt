--TEST--
Sunat SignedXml keeps RSA-SHA1 by default
--FILE--
<?php

use Greenter\XMLSecLibs\Sunat\SignedXml;

require __DIR__.'/../vendor/autoload.php';

$signer = new SignedXml();
$signer->setCertificateFromFile(__DIR__ . '/certificate.pem');

$signed = $signer->signFromFile(__DIR__ . '/invoice.xml');

$doc = new DOMDocument();
$doc->loadXML($signed);
$xpath = new DOMXPath($doc);
$xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
echo $xpath->evaluate('string(//ds:SignatureMethod/@Algorithm)'), "\n";
echo $xpath->evaluate('string(//ds:DigestMethod/@Algorithm)'), "\n";
?>
--EXPECT--
http://www.w3.org/2000/09/xmldsig#rsa-sha1
http://www.w3.org/2000/09/xmldsig#sha1
