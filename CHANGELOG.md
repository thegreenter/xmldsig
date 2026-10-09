# xmlseclibs

## Unreleased, 6.0.0
Upstream (robrichards/xmlseclibs 3.0.4 - 3.1.5):
- Reject signatures with more than one `SignedInfo` and only process `SignedInfo[1]` (CVE-2019-3465).
- Throw when canonicalization fails instead of signing/verifying `false` (3.1.4, canonicalization bypass).
- Add AES-GCM (`AES128_GCM`, `AES192_GCM`, `AES256_GCM`) and validate the authentication tag length (3.1.0, 3.1.5).
- Add `RSA_OAEP` (xmlenc11) key transport (3.1.1).
- Support `InclusiveNamespaces PrefixList` in `CanonicalizationMethod` (3.1.0).
- Strip tabs from `X509Certificate` values (3.1.2).
- Fix `X509SubjectName` using the issuer when the subject is a string.

Security (see SECURITY_AUDIT.md):
- `SignedXml::verifyXml()` verifies with the configured certificate when there is one, and no longer replaces the
  configured certificate/algorithm with the ones of the verified document. `getPublicKey($doc)` returns the embedded
  certificate without changing the instance.
- `SignedXml` verification only accepts RSA-SHA1/RSA-SHA256, SHA-1/SHA-256 digests and enveloped-signature + C14N
  transforms. Add `SignedXml::setCanonicalMethod()` (C14N, EXC-C14N).
- `SignedXml` rejects empty/invalid XML and documents with DOCTYPE, and parses with `LIBXML_NONET`.
- Reject Reference URIs that are external, unresolved or match more than one `Id` (signature wrapping).
- Reject XPath transforms during verification (`XMLSecurityDSig::$allowXPathTransforms`) and unknown transforms
  or canonicalization methods.
- Add `XMLSecurityDSig::$allowedSignatureAlgorithms`, `$allowedDigestAlgorithms`, `$allowedTransforms`.
- `XMLSecurityDSig::verify()` requires the key algorithm to match the document `SignatureMethod`; asymmetric key
  material cannot be loaded as an HMAC key; HMAC and digest comparisons use `hash_equals()`.
- Reject documents with DOCTYPE in `XMLSecurityDSig::locateSignature()` (`XMLSecurityDSig::$forbidDoctype`).
- Validate ISO 10126 padding on CBC decryption, parse decrypted XML with `LIBXML_NONET` rejecting DOCTYPE and bound
  nested `EncryptedKey`/`RetrievalMethod` references. CBC/3DES and RSA-1_5 are deprecated in favour of AES-GCM/RSA-OAEP.
- `generateGUID()`, session keys and IVs use `random_bytes()`.

## 15 Feb 2018, 5.0.0
- Rename sunatxmladapter to SignedXml
- Remove adaptesecadapter

## 15 Feb 2018, 4.1.0
- Add x509 Certificate
- Export x509 (PEM, CER)
- Remove previous converter
    
## 14 Feb 2018, 4.0.1 :heart:
- Add tool Pfx Converter
    - Convert PFX to PEM
    - Convert PFX to CER

## 02 Jan 2018, 4.0.0
- Change package name 
- Move namespaces

## 27, Dec 2017, 3.0.3
Improvements:
- Implement Sunat Sign

## ??, 2017, 3.0.1
Improvements:
- Add OneLogin to supported software

## 25, May 2017, 3.0.0
Improvements:
- Remove use of mcrypt (skymeyer)

## 08, Sep 2016, 2.0.1
Bug Fixes:
- Strip whitespace characters when parsing X509Certificate. fixes #84
  (klemen.bratec)
- Certificate 'subject' values can be arrays. fixes #80 (Andreas Stangl)
- HHVM signing node with ID attribute w/out namespace regenerates ID value.
  fixes #88 (Milos Tomic)

Improvements:
- Fix typos and add some PHPDoc Blocks. (gfaust-qb)
- Update lightSAML link. (Milos Tomic)
- Update copyright dates.

## 31, Jul 2015, 2.0.0
Features:
- Namespace support. Classes now in the RobRichards\XMLSecLibs\ namespace.

Improvements:
- Dropped support for PHP 5.2

## 31, Jul 2015, 1.4.1
Bug Fixes:
- Allow for large digest values that may have line breaks. fixes #62

Features:
- Support for locating specific signature when multiple exist in 
  document. (griga3k)

Improvements:
- Add optional argument to XMLSecurityDSig to define the prefix to be used, 
  also allowing for null to use no prefix, for the dsig namespace. fixes #13
- Code cleanup
- Depreciated XMLSecurityDSig::generate_GUID for XMLSecurityDSig::generateGUID

## 23, Jun 2015, 1.4.0
Features:
- Support for PSR-0 standard.
- Support for X509SubjectName. (Milos Tomic)
- Add HMAC-SHA1 support.

Improvements:
- Add how to install to README. (Bernardo Vieira da Silva)
- Code cleanup. (Jaime Pérez)
- Normalilze tests. (Hidde Wieringa)
- Add basic usage to README. (Hidde Wieringa)

## 21, May 2015, 1.3.2
Bug Fixes:
- Fix Undefined variable notice. (dpieper85)
- Fix typo when setting MimeType attribute. (Eugene OZ)
- Fix validateReference() with enveloping signatures

Features:
- canonicalizeData performance optimization. (Jaime Pérez)
- Add composer support (Maks3w)

## 19, Jun 2013, 1.3.1
Features:
- return encrypted node from XMLSecEnc::encryptNode() when replace is set to 
  false. (Olav)
- Add support for RSA SHA384 and RSA_SHA512 and SHA384 digest. (Jaime Prez)
- Add options parameter to the add cert methods.
- Add optional issuerSerial creation with cert

Bug Fixes:
- Fix persisted Id when namespaced. (Koen Thomeer)

Improvements:
- Add LICENSE file
- Convert CHANGELOG.txt to UTF-8

## 26, Sep 2011, 1.3.0
Features:
- Add param to append sig to node when signing. Fixes a problem when using 
  inclusive canonicalization to append a signature within a namespaced subtree.
  ex. $objDSig->sign($objKey, $appendToNode); 
- Add ability to encrypt by reference
- Add support for refences within an encrypted key
- Add thumbprint generation capability (XMLSecurityKey->getX509Thumbprint() and 
  XMLSecurityKey::getRawThumbprint($cert))
- Return signature element node from XMLSecurityDSig::insertSignature() and 
  XMLSecurityDSig::appendSignature() methods
- Support for <ds:RetrievalMethod> with simple URI Id reference.
- Add XMLSecurityKey::getSymmetricKeySize() method (Olav)
- Add XMLSecEnc::getCipherValue() method (Olav)
- Improve XMLSecurityKey:generateSessionKey() logic (Olav)

Bug Fixes:
- Change split() to explode() as split is now depreciated
- ds:References using empty or simple URI Id reference should never include 
  comments in canonicalized data.
- Make sure that the elements in EncryptedData are emitted in the correct 
  sequence.

## 11 Jan 2010, 1.2.2
Features:
- Add support XPath support when creating signature. Provides support for 
  working with EBXML documents.
- Add reference option to force creation of URI attribute. For use
  when adding a DOM Document where by default no URI attribute is added.
- Add support for RSA-SHA256

Bug Fixes:
- fix bug #5: createDOMDocumentFragment() in decryptNode when data is node 
  content (patch by Francois Wang)


## 08 Jul 2008, 1.2.1
Features:
- Attempt to use mhash when hash extension is not present. (Alfredo Cubitos).
- Add fallback to built-in sha1 if both hash and mhash are not available and 
  throw error for other for other missing hashes. (patch by Olav Morken).
- Add getX509Certificate method to retrieve the x509 cert used for Key. 
  (patch by Olav Morken).
- Add getValidatedNodes method to retrieve the elements signed by the 
  signature. (patch by Olav Morken).
- Add insertSignature method for precision signature insertion. Merge 
  functionality from appendSignature in the process. (Olav Morken, Rob).
- Finally add some tests

Bug Fixes:
- Fix canonicalization for Document node when using PHP < 5.2.
- Add padding for RSA_SHA1. (patch by Olav Morken).


## 27 Nov 2007, 1.2.0
Features:
- New addReference/List option (overwrite). Boolean flag indicating if URI
  value should be overwritten if already existing within document.
  Default is TRUE to maintain BC.

## 18 Nov 2007, 1.1.2
Bug Fixes:
- Remove closing PHP tag to fix extra whitespace characters from being output

## 11 Nov 2007, 1.1.1
Features:
- Add getRefNodeID() and getRefIDs() methods missed in previous release.
  Provide functionality to find URIs of existing reference nodes.
  Required by simpleSAMLphp project

Bug Fixes:
- Remove erroneous whitespace causing issues under certain circumastances.

## 18 Oct 2007, 1.1.0
Features:
- Enable creation of enveloping signature. This allows the creation of
  managed information cards.
- Add addObject method for enveloping signatures.
- Add staticGet509XCerts method. Chained certificates within a PEM file can
  now be added within the X509Data node.
- Add xpath support within transformations
- Add InclusiveNamespaces prefix list support within exclusive transformations.

Bug Fixes:
- Initialize random number generator for mcrypt_create_iv. (Joan Cornadó).
- Fix an interoperability issue with .NET when encrypting data in CBC mode.
  (Joan Cornadó).
