--TEST--
Reject references that point to a duplicated ID (signature wrapping)
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use Greenter\XMLSecLibs\XMLSecurityDSig;
use Greenter\XMLSecLibs\XMLSecurityKey;

$doc = new DOMDocument();
$doc->loadXML('<Root><Data Id="data1">original</Data></Root>');

$objDSig = new XMLSecurityDSig();
$objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
$objDSig->addReference($doc->documentElement->firstChild, XMLSecurityDSig::SHA256, null, array('overwrite' => false));
$objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'private'));
$objKey->loadKey(dirname(__FILE__) . '/privkey.pem', true);
$objDSig->sign($objKey, $doc->documentElement);
$signed = $doc->saveXML();

function validate($xml) {
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $dsig = new XMLSecurityDSig();
    $dsig->locateSignature($doc);
    try {
        return $dsig->validateReference() ? 'valid' : 'invalid';
    } catch (Exception $e) {
        return $e->getMessage();
    }
}

echo validate($signed), "\n";
// Attacker inserts a second element with the same Id before the signed one.
echo validate(str_replace('<Root>', '<Root><Data Id="data1">tampered</Data>', $signed)), "\n";
?>
--EXPECT--
valid
Duplicate ID found: data1
