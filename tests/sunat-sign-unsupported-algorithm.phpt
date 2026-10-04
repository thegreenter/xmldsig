--TEST--
Sunat SignedXml rejects unsupported signature and digest algorithms
--FILE--
<?php

use Greenter\XMLSecLibs\Sunat\SignedXml;
use Greenter\XMLSecLibs\XMLSecurityDSig;
use Greenter\XMLSecLibs\XMLSecurityKey;

require __DIR__.'/../vendor/autoload.php';

$signer = new SignedXml();
try {
    $signer->setSignatureAlgorithm(XMLSecurityKey::DSA_SHA1);
} catch (InvalidArgumentException $e) {
    echo $e->getMessage(), "\n";
}
try {
    $signer->setDigestAlgorithm(XMLSecurityDSig::RIPEMD160);
} catch (InvalidArgumentException $e) {
    echo $e->getMessage(), "\n";
}
?>
--EXPECT--
Unsupported signature algorithm: http://www.w3.org/2000/09/xmldsig#dsa-sha1
Unsupported digest algorithm: http://www.w3.org/2001/04/xmlenc#ripemd160
