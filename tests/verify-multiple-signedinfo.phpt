--TEST--
Reject Signature with more than one SignedInfo (CVE-2019-3465)
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use Greenter\XMLSecLibs\XMLSecurityDSig;
use Greenter\XMLSecLibs\XMLSecurityKey;

$doc = new DOMDocument();
$doc->load(dirname(__FILE__) . '/basic-doc.xml');

$objDSig = new XMLSecurityDSig();
$objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
$objDSig->addReference($doc, XMLSecurityDSig::SHA256, array('http://www.w3.org/2000/09/xmldsig#enveloped-signature'));
$objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'private'));
$objKey->loadKey(dirname(__FILE__) . '/privkey.pem', true);
$objDSig->sign($objKey, $doc->documentElement);

$xpath = new DOMXPath($doc);
$xpath->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
$signedInfo = $xpath->query('//ds:Signature/ds:SignedInfo')->item(0);
$signedInfo->parentNode->appendChild($signedInfo->cloneNode(true));

$verifier = new XMLSecurityDSig();
try {
    $verifier->locateSignature($doc);
    echo "FAIL: locateSignature accepted\n";
} catch (Exception $e) {
    echo $e->getMessage(), "\n";
}
?>
--EXPECT--
Invalid structure - Too many SignedInfo elements found
