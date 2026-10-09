--TEST--
Reject signatures with more than one SignedInfo (CVE-2019-3465)
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use Greenter\XMLSecLibs\XMLSecurityDSig;

$doc = new DOMDocument();
$doc->load(dirname(__FILE__) . '/sign-formatted-test.xml');

$xpath = new DOMXPath($doc);
$xpath->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
$signedInfo = $xpath->query('//ds:Signature/ds:SignedInfo')->item(0);
$signedInfo->parentNode->appendChild($signedInfo->cloneNode(true));

$objXMLSecDSig = new XMLSecurityDSig();
try {
    $objXMLSecDSig->locateSignature($doc);
    echo "locateSignature: accepted\n";
} catch (Exception $e) {
    echo "locateSignature: ", $e->getMessage(), "\n";
}

$objXMLSecDSig->sigNode = $xpath->query('//ds:Signature')->item(0);
try {
    $objXMLSecDSig->canonicalizeSignedInfo();
    echo "canonicalizeSignedInfo: accepted\n";
} catch (Exception $e) {
    echo "canonicalizeSignedInfo: ", $e->getMessage(), "\n";
}
?>
--EXPECT--
locateSignature: Invalid structure - Too many SignedInfo elements found
canonicalizeSignedInfo: Invalid structure - Too many SignedInfo elements found
