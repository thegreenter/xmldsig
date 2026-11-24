--TEST--
AES-GCM encryption round trip and authentication tag validation
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use Greenter\XMLSecLibs\XMLSecurityKey;
use Greenter\XMLSecLibs\XMLSecEnc;

$arTests = array(
    'AES128_GCM' => XMLSecurityKey::AES128_GCM,
    'AES192_GCM' => XMLSecurityKey::AES192_GCM,
    'AES256_GCM' => XMLSecurityKey::AES256_GCM,
);

foreach ($arTests as $testName => $testKey) {
    print "$testName: ";

    $dom = new DOMDocument();
    $dom->load(dirname(__FILE__) . '/basic-doc.xml');
    $original = $dom->saveXML($dom->documentElement);

    $objKey = new XMLSecurityKey($testKey);
    $objKey->generateSessionKey();

    $enc = new XMLSecEnc();
    $enc->setNode($dom->documentElement);
    $enc->type = XMLSecEnc::ELEMENT;
    $encNode = $enc->encryptNode($objKey, false);

    $dec = new XMLSecEnc();
    $dec->setNode($encNode);
    $dec->type = XMLSecEnc::ELEMENT;
    $decrypted = $dec->decryptNode($objKey, false);
    print ($decrypted === $original ? 'roundtrip' : 'roundtrip FAILED');

    // Tampered authentication tag must be rejected.
    $cipherValue = $encNode->getElementsByTagNameNS(XMLSecEnc::XMLENCNS, 'CipherValue')->item(0);
    $raw = base64_decode($cipherValue->textContent);
    $raw[strlen($raw) - 1] = chr(ord($raw[strlen($raw) - 1]) ^ 0x01);
    $cipherValue->nodeValue = base64_encode($raw);
    try {
        $dec->decryptNode($objKey, false);
        print ', tampered tag accepted';
    } catch (Exception $e) {
        print ', tampered tag rejected';
    }

    // Truncated payload (shorter than the tag) must be rejected.
    $cipherValue->nodeValue = base64_encode(substr($raw, 0, 20));
    try {
        $dec->decryptNode($objKey, false);
        print ", truncated accepted\n";
    } catch (Exception $e) {
        print ", truncated rejected\n";
    }
}
?>
--EXPECT--
AES128_GCM: roundtrip, tampered tag rejected, truncated rejected
AES192_GCM: roundtrip, tampered tag rejected, truncated rejected
AES256_GCM: roundtrip, tampered tag rejected, truncated rejected
