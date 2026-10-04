--TEST--
Sunat SignedXml with RSA-SHA256 signature and SHA256 digest
--FILE--
<?php

use Greenter\XMLSecLibs\Sunat\SignedXml;
use Greenter\XMLSecLibs\XMLSecurityDSig;
use Greenter\XMLSecLibs\XMLSecurityKey;

require __DIR__.'/../vendor/autoload.php';

$signer = new SignedXml();
$signer->setSignatureAlgorithm(XMLSecurityKey::RSA_SHA256);
$signer->setDigestAlgorithm(XMLSecurityDSig::SHA256);
$signer->setCertificateFromFile(__DIR__ . '/certificate.pem');

$signed = $signer->signFromFile(__DIR__ . '/invoice.xml');

$doc = new DOMDocument();
$doc->loadXML($signed);
$xpath = new DOMXPath($doc);
$xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
echo $xpath->evaluate('string(//ds:SignatureMethod/@Algorithm)'), "\n";
echo $xpath->evaluate('string(//ds:DigestMethod/@Algorithm)'), "\n";

// Verify without a configured certificate: the algorithm is read from the signature.
$verifier = new SignedXml();
var_dump($verifier->verifyXml($signed));

$tampered = str_replace('<cbc:PayableAmount currencyID="PEN">200', '<cbc:PayableAmount currencyID="PEN">100', $signed);
var_dump((new SignedXml())->verifyXml($tampered));
?>
--EXPECT--
http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
http://www.w3.org/2001/04/xmlenc#sha256
bool(true)
bool(false)
