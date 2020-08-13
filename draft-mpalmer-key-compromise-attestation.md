---
title: "A Standard Format for Key Compromise Attestation"
abbrev: "Key Compromise Attestation"
docname: draft-mpalmer-key-compromise-attestation-latest
category: exp

ipr: trust200902
area: Security
workgroup: Individual Submission
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: M. Palmer
    name: Matt Palmer
    organization: pwnedkeys.com
    email: mpalmer@hezmatt.org

informative:
  SEC1:
    title: 'SEC 1: Elliptic Curve Cryptography'
    author:
      org: Standards for Efficient Cryptography Group (SECG)
    date: September 2000
  DWK:
    title: 'DSA-1571-1 openssl -- predictable random number generator'
    author:
      org: The Debian Project
    target: 'https://www.debian.org/security/2008/dsa-1571'
    date: May 2008

--- abstract

This document describes a profile for a PKCS#10 Certificate Signing Request (CSR)
that attests with reasonable confidence that the key which signed the CSR has
been compromised.

--- middle

# Introduction

When a private key becomes compromised through disclosure or intrusion, it can be
difficult to safely and conclusively demonstrate to third parties that the key is, in fact, compromised.
Different parties have different standards of proof, and the tools available to them may
differ.  In many cases, the lowest-common-denominator approach, that of providing the
actual compromised private key, is used, which increases the risk of further disclosure
and the associated hazards.

This document describes a specific profile for a PKCS#10 {{!RFC2986}} Certificate Signing Request
(CSR) which provides a reliable attestation that a private key has been compromised.  The
use of an existing format allows re-use of existing tools for generating and validating
the CSR, whilst minimising the risk of inadvertent misuse of a CSR generated for another
purpose.


# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{!RFC2119}} {{!RFC8174}}
when, and only when, they appear in all capitals, as shown here.


# Purpose and Goals of a Key Compromise Attestation

An attestation of key compromise is a document which verifiably attests that
a private key is no longer private.  This destroys the utility of that key for
cryptographic operations, as the fundamental assumption of the private key -- that it
is private -- no longer holds.

An attestation of key compromise should be useable by both first parties (the
legitimate "owner" of the private key) as well as third parties (anyone who
happens to come across a compromised private key and wishes to attest that it
has been compromised).  It must be durable and reliable, in that it must not
expire or otherwise become significantly less trustworthy over time.  It must
also not require the real-time possession of the private key itself, to allow
for attestation of compromise even in situations where the access to the key
material has been lost or is not kept permanently online.

Ideally, a key compromise attestation should be simple to generate and verify
with existing tools, and not require extensive new code or infrastructure to be
useful.


# Structure of a Key Compromise Attestation

The format of a key compromise attestation is a PKCS#10 {{!RFC2986}} Certificate Signing
Request (CSR), with a specified subject and extension to minimise the chances of it
being mistaken for a legitimate CSR useful for some other purpose.

The CSR format was chosen because it is already in wide use for ad hoc attestation of
key compromise, and as such has wide existing support for verification and handling.
A very constrained CSR profile is specified to enhance resistance to collision attacks against
the hashes used in signatures.

## CSR Subject

The subject field of a key compromise attestation CSR MUST be a distinguished
name which contains only a CN field, with the value "kca=v1 This Key Is Compromised" (without
the quotes) as a UTF8String.

Additional fields SHOULD NOT appear in the subject of the CSR, as they may be used to
provide attacker-controlled prefix data.


## CSR Subject Public Key

The subjectPKInfo field of the key compromise attestation CSR MUST be the
SubjectPublicKeyInfo of the key which is attested as having been compromised.


## CSR Attributes

A key compromise attestation CSR MUST contain an Attributes section with a
single attribute, an extensionRequest {{!RFC2985}}.  The extensionRequest, in
turn, MUST contain a single extension, a NoSecurityAfforded {{!RFC7169}}
extension, with a value of TRUE.  Per {{RFC7169}}, this extension MUST be
marked critical.


## CSR Signature

The signature carried by the CSR MUST be made by the key which is attested as having been
compromised.


# Security Considerations

As the consequences for erroneously generating, disseminating, or accepting a
key compromise attestation can be significant (the complete loss of utility of
a key or key-using artifact, such as a certificate), it is important that
compromise attestations are securely generated and validated before use.


## Generating Key Compromise Attestations

An attestation of key compromise is a potent service denial tool in the wrong
hands.  As such, a key compromise attestation should never be generated for a
key which is not (yet) compromised, unless the resulting attestation will be
carefully secured against disclosure.  While the improper disclosure of a
compromise attestation is not as catastrophic as a key compromise, it can
certainly have unwanted consequences.

Key compromise attestations do not introduce any new security issues for
systems which are capable of signing arbitrary data, although the consequences
of signing the wrong thing are somewhat different.  If a miscreant is capable
of coercing a system into signing a key compromise attestation, this could be
used to deny further use of the key.  However, the potential for mischief if a
miscreant is capable of signing arbitrary data is already significant.


## Processing Key Compromise Attestations

The consequences of incorrectly accepting an invalid attestation of key
compromise can be significant.  As such, it is important that any attestation
should be carefully examined to ensure its validity before it is relied upon.

The first thing that MUST be checked on any attestation is the signature.
This signature SHOULD be validated against the subjectPublicKeyInfo in the CSR.
If the signature does not validate, then under no circumstances should the
attestation be relied upon for any purpose.

Given a valid signature, the subjectPKInfo in the CSR MUST be compared against
the subjectPublicKey info of the key(s) which are to be checked for compromise.
This MAY be done via direct comparison, or via comparison of a SHA256 (or
equivalently robust) hash of the keys.  However, it is important to bear in
mind that some key formats, in particular elliptic curve keys {{SEC1}}, have
multiple valid representations.  The subjectPublicKeyInfo data in both the CSR
and the key(s) in use MUST be normalised to a common format before comparison,
to avoid false negatives.

The subject of the CSR should be checked to ensure it indicates that the CSR
is a Key Compromise Attestation, and not a regular CSR.  The prefix "kca=v1 "
in the CN field indicates the version of the attestation, while the remainder
of the field is a more human-readable indication that the key is compromised
and should not be used.

Ensuring the presence of the NoSecurityAfforded extension is of lesser
importance, as its presence is primarily to prevent the accidental use of the
compromise attestation CSR for other purposes.  Any system which validates
attributes in a CSR before use should fail to process the extension (as it MUST
be marked critical), while any system which blindly copies attributes from the
CSR to the eventual certificate will produce a certificate which, once again,
will fail to validate.  Systems which blindly copy attributes from a CSR to a
certificate whilst resetting the critical flag are beyond help.

Because key compromise attestations do not expire, and do not need to be
"refreshed" on a regular basis, it is possible that over time attestations may
exist whose signatures use hash algorithms which are not considered
particularly strong at the time of comparison.  Processors of key compromise
attestations SHOULD reject a key compromise attestation which uses a signature
algorithm known to be weak to second pre-image attacks, and which also contains
additional subject distinguished name fields and/or attributes and extensions.

When a valid key compromise attestation is received, all use of the compromised
key should cease as soon as possible.  Further, the compromised key SHOULD be
remembered as compromised, to prevent the inadvertent reuse of that key in the
future.  Whilst storage of a potentially unbounded list of banned keys is
problematic, it is important to bear in mind that a compromised key is
compromised forever.  Debian weak keys {{DWK}} have been spotted being used in
the wild over a decade after their existence was first revealed, and there is
no reason to believe that other compromised keys may not have similar longevity.

Systems which receive key compromise attestations from the public must bear in
mind that generating many keys, and hence generating many attestations of
compromise, is a trivial exercise.  If the work required to process a key
compromise attestation (such as examining all in-use accounts or certificates
to see if they use an attested-compromised key) is significantly greater than
the work required to generate a key compromise attestation, it is recommended that
defences against Denial of Service attacks due to "flooding" attestations
be implemented.

Repeated submission of attestations for the same compromised key should not,
in general, cause problems for a properly-implemented system.  Once a valid
attestation has been received, all use of that key should cease.  Therefore,
if another compromise attestation for the same key is received, it should be
sufficient to verify that the key is already in the "banned keys" list, without
going through the entire attestation handling chain again.


# IANA Considerations

This document has no IANA actions.



--- back

# Acknowledgments
{:numbered="false"}

The author acknowledges the contributions of the many, many people who leave
their private keys in public places, providing such a wealth of opportunity for
handling and reporting their compromise to the appropriate parties.
