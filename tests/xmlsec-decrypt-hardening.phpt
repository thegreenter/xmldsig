--TEST--
Decryption hardening: CBC padding, decrypted DOCTYPE and nested key references
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use Greenter\XMLSecLibs\XMLSecurityKey;
use Greenter\XMLSecLibs\XMLSecEnc;

function encryptDecrypt($payload, $type, $tamper = null)
{
    $dom = new DOMDocument();
    $dom->loadXML('<root><data>x</data></root>');
    $key = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
    $key->generateSessionKey();

    $enc = new XMLSecEnc();
    $enc->setNode($dom->documentElement->firstChild);
    $enc->type = XMLSecEnc::CONTENT;
    $encNode = $enc->encryptNode($key, false);
    $cipherValue = $encNode->getElementsByTagNameNS(XMLSecEnc::XMLENCNS, 'CipherValue')->item(0);
    $cipherValue->nodeValue = base64_encode($key->encryptData($payload));
    if ($tamper) {
        $cipherValue->nodeValue = base64_encode($tamper(base64_decode($cipherValue->nodeValue)));
    }
    $dom->documentElement->appendChild($dom->importNode($encNode, true));

    $dec = new XMLSecEnc();
    $dec->setNode($dom->documentElement->lastChild);
    $dec->type = $type;
    try {
        $result = $dec->decryptNode($key, true);
        return $result instanceof DOMNode ? 'ok' : 'unexpected';
    } catch (Exception $e) {
        return $e->getMessage();
    }
}

echo 'element: ', encryptDecrypt('<a>b</a>', XMLSecEnc::ELEMENT), "\n";
echo 'doctype: ', encryptDecrypt('<!DOCTYPE a [<!ENTITY e "x">]><a>&e;</a>', XMLSecEnc::ELEMENT), "\n";
echo 'invalid: ', encryptDecrypt('<a>', XMLSecEnc::ELEMENT), "\n";
echo 'bad padding: ', encryptDecrypt('<a>b</a>', XMLSecEnc::ELEMENT, function ($raw) {
    // Flip the last byte of the IV-adjacent block so the padding byte becomes invalid.
    $raw[strlen($raw) - 17] = chr(ord($raw[strlen($raw) - 17]) ^ 0x20);
    return $raw;
}), "\n";

// EncryptedKey that references itself through RetrievalMethod.
$xml = '<root xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
    . '<xenc:EncryptedKey Id="k"><xenc:EncryptionMethod Algorithm="' . XMLSecurityKey::RSA_OAEP_MGF1P . '"/>'
    . '<ds:KeyInfo><ds:RetrievalMethod Type="http://www.w3.org/2001/04/xmlenc#EncryptedKey" URI="#k"/></ds:KeyInfo>'
    . '<xenc:CipherData><xenc:CipherValue>AA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></root>';
$doc = new DOMDocument();
$doc->loadXML($xml);
try {
    XMLSecurityKey::fromEncryptedKeyElement($doc->documentElement->firstChild);
    echo "recursion: accepted\n";
} catch (Exception $e) {
    echo 'recursion: ', $e->getMessage(), "\n";
}
?>
--EXPECT--
element: ok
doctype: A DOCTYPE is not allowed in decrypted XML
invalid: Unable to parse decrypted XML
bad padding: Failure decrypting Data (openssl symmetric)
recursion: Too many nested EncryptedKey references
