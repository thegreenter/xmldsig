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
    public function setCertificate($privateKey);

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
