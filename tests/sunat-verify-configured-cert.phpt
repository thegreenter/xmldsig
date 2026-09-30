--TEST--
Sunat SignedXml verify() with a configured certificate uses the algorithm of the signature
--FILE--
<?php

use Greenter\XMLSecLibs\Sunat\SignedXml;
use Greenter\XMLSecLibs\XMLSecurityDSig;
use Greenter\XMLSecLibs\XMLSecurityKey;

require __DIR__.'/../vendor/autoload.php';

$certPath = __DIR__ . '/certificate.pem';

function signed($signatureAlgorithm, $digestAlgorithm, $certPath)
{
    $signer = new SignedXml();
    $signer->setSignatureAlgorithm($signatureAlgorithm);
    $signer->setDigestAlgorithm($digestAlgorithm);
    $signer->setCertificateFromFile($certPath);

    $doc = new DOMDocument();
    $doc->load(__DIR__ . '/invoice.xml');
    $signer->sign($doc);

    return $doc;
}

$sha256 = signed(XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::SHA256, $certPath);
$sha1 = signed(XMLSecurityKey::RSA_SHA1, XMLSecurityDSig::SHA1, $certPath);

// Default instance (SHA-1) verifying a SHA-256 signature.
$verifier = new SignedXml();
$verifier->setCertificateFromFile($certPath);
var_dump($verifier->verify($sha256));

// SHA-256 instance verifying a SHA-1 signature.
$verifier = new SignedXml();
$verifier->setSignatureAlgorithm(XMLSecurityKey::RSA_SHA256);
$verifier->setCertificateFromFile($certPath);
var_dump($verifier->verify($sha1));
?>
--EXPECT--
bool(true)
bool(true)
