<?php

namespace Greenter\XMLSecLibs\Sunat;

use DOMDocument;
use RuntimeException;

/**
 * Interface for XML Digital Signature adapters.
 *
 * These methods and URIs follows the "XML Signature Syntax and Processing"
 * recommendation published by W3C.
 *
 * @see http://www.w3.org/TR/xmldsig-core/ "XML Signature Syntax and Processing"
 */
interface AdapterInterface
{
    /**
     * Algorithm identifiers.
     *
     * @see http://www.w3.org/TR/xmldsig-core/#sec-AlgID
     */

    /* Signature */
    /** @var string DSA with SHA1 (DSS) Sign Algorithm URI */
    const DSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#dsa-sha1';

    /* Transform */
    const ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

    /**
     * Set the private key for data sign.
     *
     * @param string $privateKey    Key in PEM format
     *
     * @return void
     *
     * @see AdapterInterface::DSA_SHA1
     * @see AdapterInterface::RSA_SHA1
     */
    public function setPrivateKey($privateKey);

    /**
     * Set the public key.
     *
     * @param string $publicKey Key in PEM format
     *
     * @return void
     */
    public function setPublicKey($publicKey);

    /**
     * Returns the public key from various sources.
     *
     * Try to get the public key from the following sources (index means priority):
     *
     *  1) From $dom param of this method
     *  2) From a previous publickey set by setPublicKey
     *  3) From private key set by setPrivateKey
     *
     * @param null|DOMDocument $doc DOM node where to search a publicKey
     *
     * @return string|null Public key in PEM format
     */
    public function getPublicKey(DOMDocument $doc = null);

    /**
     * Public/Private key signature algorithm.
     *
     * @return string|null Algorithm URI
     */
    public function getKeyAlgorithm();

    /**
     * Add the "signature" element to the DOM Document.
     *
     * @param DOMDocument $data Data to sign
     *
     * @return void
     *
     * @throws RuntimeException If is not possible do the signature
     */
    public function sign(DOMDocument $data);

    /**
     * Validate the signature of the DOM Document.
     *
     * @param DOMDocument $data Data to verify
     *
     * @return bool TRUE if is correct or FALSE otherwise
     *
     * @throws RuntimeException If is not possible do the verification
     */
    public function verify(DOMDocument $data);
}
