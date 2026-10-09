--TEST--
AES-GCM encryption round trip and authentication tag validation
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use Greenter\XMLSecLibs\XMLSecurityKey;

$algorithms = array(
    XMLSecurityKey::AES128_GCM,
    XMLSecurityKey::AES192_GCM,
    XMLSecurityKey::AES256_GCM,
);
foreach ($algorithms as $algorithm) {
    $key = new XMLSecurityKey($algorithm);
    $key->generateSessionKey();
    $encrypted = $key->encryptData('Mensaje secreto');
    echo $key->decryptData($encrypted), "\n";

    // Flip one bit of the ciphertext: the authentication tag must reject it.
    $tampered = $encrypted;
    $tampered[13] = chr(ord($tampered[13]) ^ 1);
    try {
        $key->decryptData($tampered);
        echo "FAIL: tampered data accepted\n";
    } catch (Exception $e) {
        echo "tampered rejected\n";
    }

    try {
        $key->decryptData(substr($encrypted, 0, 20));
        echo "FAIL: truncated data accepted\n";
    } catch (Exception $e) {
        echo "truncated rejected\n";
    }
}
?>
--EXPECT--
Mensaje secreto
tampered rejected
truncated rejected
Mensaje secreto
tampered rejected
truncated rejected
Mensaje secreto
tampered rejected
truncated rejected
