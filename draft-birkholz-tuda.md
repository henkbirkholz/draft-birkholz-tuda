---
title: 'Time-Based Uni-Directional Attestation'
abbrev: tuda
docname: draft-birkholz-i2nsf-tuda-latest
date: 2018-05-02
stand_alone: true
#coding: us-ascii
ipr: trust200902
area: ''
wg: ''
kw: Internet-Draft
cat: info
pi: [toc, sortrefs, symrefs, comments]
author:
- ins: A. Fuchs
  name: Andreas Fuchs
  org: Fraunhofer Institute for Secure Information Technology
  abbrev: Fraunhofer SIT
  email: andreas.fuchs@sit.fraunhofer.de
  street: Rheinstrasse 75
  code: '64295'
  city: Darmstadt
  country: Germany
- ins: H. Birkholz
  name: Henk Birkholz
  org: Fraunhofer Institute for Secure Information Technology
  abbrev: Fraunhofer SIT
  email: henk.birkholz@sit.fraunhofer.de
  street: Rheinstrasse 75
  code: '64295'
  city: Darmstadt
  country: Germany
- ins: I. McDonald
  name: Ira E McDonald
  org: High North Inc
  abbrev: High North Inc
  email: blueroofmusic@gmail.com
  street: PO Box 221
  code: '49839'
  city: Grand Marais
  country: US
- ins: C. Bormann
  name: Carsten Bormann
  org: Universitaet Bremen TZI
  street:
  - Bibliothekstr. 1
  city: Bremen
  code: D-28359
  country: Germany
  phone: +49-421-218-63921
  email: cabo@tzi.org
normative:
  RFC2119:

informative:
  RFC4949:
  RFC2790:
  RFC6933:
  RFC1213:
  # RFC3410: STD62
  RFC3418:
  RFC7049: cbor
  STD62:
    title: Internet Standard 62
    author:
    seriesinfo:
      STD: 62
      RFCs: 3411 to 3418
    date: 2002-12
  I-D.greevenbosch-appsawg-cbor-cddl: cddl
  I-D.ietf-sacm-terminology: sacmterm
  I-D.ietf-core-comi: comi
  I-D.ietf-sacm-coswid: coswid
  SCALE:
    title: Improving Scalability for Remote Attestation
    author:
      ins: A. Fuchs
      name: Andreas Fuchs
    date: 2008
    seriesinfo:
      Master Thesis (Diplomarbeit),: Technische Universitaet Darmstadt, Germany
  PRIRA:
    title: Principles of Remote Attestation
    author:
    - ins: G. Coker
      name: George Coker
    - ins: J. Guttman
      name: Joshua Guttman
    - ins: P. Loscocco
      name: Peter Loscocco
    - ins: A. Herzog
      name: Amy Herzog
    - ins: J. Millen
      name: Jonathan Millen
    - ins: B. O'Hanlon
      name: Brian O'Hanlon
    - ins: J. Ramsdell
      name: John Ramsdell
    - ins: A. Segall
      name: Ariel Segall
    - ins: J. Sheehy
      name: Justin Sheehy
    - ins: B. Sniffen
      name: Brian Sniffen
    seriesinfo:
      Springer: International Journal of Information Security, Vol. 10, pp. 63-81
      DOI: 10.1007/s10207-011-0124-7
    date: 2011-04-23
  SFKE2008:
    title: Improving the scalability of platform attestation
    author:
    - ins: F. Stumpf
      name: Frederic Stumpf
    - ins: A. Fuchs
      name: Andreas Fuchs
    - ins: S. Katzenbeisser
      name: Stefan Katzenbeisser
    - ins: C. Eckert
      name: Claudia Eckert
    seriesinfo:
      ACM: >
        Proceedings of the 3rd ACM workshop on Scalable trusted computing - STC '08
      page: 1-10
      DOI: 10.1145/1456455.1456457
    date: 2008
  TPM12:
    title: >
      Information technology -- Trusted Platform Module -- Part 1: Overview
    seriesinfo:
      ISO/IEC: 11889-1
    date: 2009
  TPM2:
    title: >
      Trusted Platform Module Library Specification, Family 2.0, Level 00, Revision 01.16 ed.,
      Trusted Computing Group
    date: 2014
  TEE:
    title: >
      TEE System Architecture v1.1, GPD_SPE_009
    author:
    - org: Global Platform
    date: 2017
  PTS:
    target: https://www.trustedcomputinggroup.org/wp-content/uploads/IFM_PTS_v1_0_r28.pdf
    title: TCG Attestation PTS Protocol Binding to TNC IF-M
    author:
    - org: TCG TNC Working Group
    date: 2011
  TCGGLOSS:
    target: https://www.trustedcomputinggroup.org/wp-content/uploads/TCG_Glossary_Board-Approved_12.13.2012.pdf
    title: TCG Glossary
    author:
    - org: TCG
    date: 2012
  AIK-Enrollment:
    target: https://www.trustedcomputinggroup.org/wp-content/uploads/IWG_CMC_Profile_Cert_Enrollment_v1_r7.pdf
    title: A CMC Profile for AIK Certificate Enrollment
    author:
    - org: TCG Infrastructure Working Group
    date: 2011
  AIK-Credential:
    target: https://www.trustedcomputinggroup.org/wp-content/uploads/IWG-Credential_Profiles_V1_R1_14.pdf
    title: TCG Credential Profile
    author:
    - org: TCG Infrastructure Working Group
    date: 2007
  REST:
    target: http://www.ics.uci.edu/~fielding/pubs/dissertation/fielding_dissertation.pdf
    title: Architectural Styles and the Design of Network-based Software Architectures
    author:
    - ins: R. Fielding
      name: Roy Fielding
      org: University of California, Irvine
    date: 2000
    seriesinfo:
      Ph.D.: Dissertation, University of California, Irvine
  RFC3161: timestamp
  RFC3411: snmp
  RFC7320: lawn
  RFC7519: jwt
  RFC7230: http1
  RFC7252: coap
  RFC7540: http2
  RFC6690: link
  RFC8040: restconf
  IEEE802.1AR:
    title: 802.1AR-2009 - IEEE Standard for Local and metropolitan area networks - Secure Device Identity
    author:
      org: IEEE Computer Society
    date: 2009
    seriesinfo:
      IEEE: Std 802.1AR
  IEEE1609:
    title: 1609.4-2016 - IEEE Standard for Wireless Access in Vehicular Environments (WAVE) -- Multi-Channel Operation
    author:
      org: IEEE Computer Society
    date: 2016
    seriesinfo:
      IEEE: Std 1609.4

--- abstract

This memo documents the method and bindings used to conduct time-based uni-directional attestation between distinguishable endpoints over the network.

--- middle

# Introduction

Remote attestation describes the attempt to determine and appraise properties, such as integrity and trustworthiness, of an endpoint --- the Attestor --- over a network to another endpoint --- the Verifier --- without direct access. Typically, this kind of appraisal is based on integrity measurements of software components right before they are loaded as software instances on the Attestor. In general, attestation procedures are utilizing a hardware root of trust (RoT). The TUDA protocol family uses hash values of all started software components that are stored (extended into) a Trust-Anchor (the Rot) implemented as a Hardware Security Module (e.g. a Trusted Platform Module or similar) and are reported via a signature over those measurements.

This draft introduces the concept of including the exchange of evidence (created via a hardware root of trust containing an shielded secret that is unknown to the user in order to increase the confidence that a communication peer is a Trusted System {{RFC4949}}. In consequnce, this document introduces the term forward authenticity.

Forward Authenticity (FA):

: A property of secure communication protocols, in which later compromise of the long-term keys of a data origin does not compromise past authentication of data from that origin. FA is achieved by timely recording of assessments of the authenticity from entities (via "audit logs" during "audit sessions") that are authorized for this purpose, in a time frame much shorter than that expected for the compromise of the long-term keys.

Forward Authenticity enables new level of guarantee and can be included in the basically every protocol, such as ssh, router advertisements, link layer neighbor discover, or even ICMP echo.

## Remote Attestation

In essence, remote attestation (RA) is composed of three activities. The following definitions are derived from the definitions presented in {{PRIRA}} and {{TCGGLOSS}}.

Attestation:

: The creation of one ore more claims about the properties of an Attestor, such that the claims can be used as evidence.

Conveyance:

: The transfer of evidence from the Attestor to the Verifier via an interconnect. 

Verification: 

: The appraisal of evidence by evaluating it against declarative guidance.

With TUDA, the claims that compose the evidence are signatures over trustworthy integrity measurements created by leveraging a hardware RoT. The evidence is appraised via corresponding signatures over reference integrity measurements (RIM, represented, for example via {{-coswid}}).

Protocols that facilitate Trust-Anchor based signatures in order to provide
RATS are usually bi-directional challenge/response protocols, such as the Platform Trust Service protocol {{PTS}} or CAVES {{PRIRA}}, where one entity sends a challenge that is included inside the response to prove the recentness --- the freshness (see fresh in {{RFC4949}}) --- of the attestation information. The corresponding interaction model tightly couples the three activities of creating, transferring and appraising evidence.

The Time-Based Uni-directional Attestation family of protocols --- TUDA --- described in this document can decouple the three activities RATS are composed of. As a result, TUDA provides additional capabilities, such as:

* remote attestation for Attestors that might not always be able to reach the Internet by enabling the verification of past states,
* secure audit logs by combining the evidence created via TUDA with integrity measurement logs that represent a detailed record of corresponding past states,
* an uni-directional interaction model that can traverse "diode-like" network security functions (NSF) or can be leveraged in RESTful architectures (e.g. CoAP {{-coap}}), analogously.

## Evidence Creation

TUDA is a family of protocols that bundles results from specific attestation activities. The attestation activities of TUDA are based on a hardware Root of Trust that provides the following capabilities:

* Platform Configuration Registers (PCR) that store measurements consecutively (corresponding terminology: "to extend a PCR") and represent the chain of measurements as a single measurement value ("PCR value"),
* Restricted Signing Keys (RSK) that can only be accessed, if a specific signature about measurements can be provided as authentication, and
* a dedicated source of (relative) time, e.g. a tick counter.

## Evidence Appraisal

To appraise the evidence created by an Attestor, the Verifier requires corresponding Reference Integrity Measurements (RIM). Typically, a set of RIM are bundled in a RIM-Manifest (RIMM). The scope of a manifest encompasses, e.g., a platform, a device, a computing context, or a virtualised function. In order to be comparable, the hashing algorithms used by the Attestor to create the integrity measurements have to match the hashing algorithms used to create the corresponding RIM that are used by the Verifier to appraise the integrity evidence.

## Activities and Actions

Depending on the platform (i.e. one or more computing contexts including a dedicated hardware RoT), a generic RA activity results in platform-specific actions that have to be conducted. In consequence, there are multiple specific operations and data models (defining the input and output of operations). Hence, specific actions are are not covered by this document. Instead, the requirements on operations and the information elements that are the input and output to these operations are illustrated using pseudo code in [FIXME Appendix foo].

## Attestation and Verification

Both the attestation and the verification activity of TUDA also require a trusted Time Stamp Authority (TSA) as an additional third party next to the Attestor and the Verifier.
The protocol uses a Time Stamp Authority based on {{RFC3161}}. The combination of the local source of time provided by the hardware RoT (located on the Attestor) and the Time Stamp Tokens provided by the TSA (to both the Attestor and the Verifier) enable the attestation and verification of an appropriate freshness of the evidence conveyed by the Attestor --- without requiring a challenge/response interaction model that uses a nonce to ensure the freshness.

Typically, the verification activity requires declarative guidance (representing desired or compliant endpoint characteristics in the form of RIM, see above) to appraise the individual integrity measurements the conveyed evidence is composed on. The acquisition or representation (data models) of declarative guidance as well as the corresponding evaluation methods are out of the scope of this document.

## Information Elements and Conveyance

TUDA defines a set of information elements (IE) that are created and stored on the Attestor and are intended to be transferred to the Verifier in order to enable appraisal. Each TUDA IE:

* is encoded in the Concise Binary Object Representation (CBOR {{-cbor}}) to minimize the volume of data in motion. In this document, the composition of the CBOR data items that represent IE is described using the Concise Data Definition Language, CDDL {{-cddl}}
* that requires a certain freshness is only created/updated when out-dated, which reduces the overall resources required from the Attestor, including the utilization of the hardware root of trust. The IE that have to be created are determined by their age or by specific state changes on the Attestor (e.g. state changes due to a reboot-cycle)
* is only transferred when required, which reduces the amount of data in motion necessary to conduct remote attestation significantly. Only IE that have changed since their last conveyance have to be transferred
* that requires a certain freshness can be reused for multiple remote attestation procedures in the limits of its corresponding freshness-window, further reducing the load imposed on the Attestor and its corresponding hardware RoT.

## TUDA Objectives

The Time-Based Uni-directional Attestation family of protocols is designed to:

* increase the confidence in authentication and authorization procedures,
* address the requirements of constrained-node networks,
* support interaction models that do not maintain connection-state over time, such as REST architectures {{REST}},
* be able to leverage existing management interfaces, such as SNMP {{-snmp}}. RESTCONF {{-restconf}} or CoMI {{-comi}} --- and corresponding bindings,
* support broadcast and multicast schemes (e.g. {{IEEE1609}}),
* be able to cope with temporary loss of connectivity, and to
* provide trustworthy audit logs of past endpoint states.

## Hardware Dependencies

The binding of the attestation scheme used by TUDA to generate the TUDA IE is specific to the methods provided by the hardware RoT used (see above). In this document,expositional text and pseudo-code that is provided as a reference to instantiate the TUDA IE is based on TPM 1.2 and TPM 2.0 operations. The corresponding TPM commands are specified in {{TPM12}} and {{TPM2}}. The references to TPM commands and corresponding pseudo-code only serve as guidance to enable a better understanding of the attestation scheme and is intended to encourage the use of any appropriate hardware RoT or equivalent set of functions available to a CPU or Trusted Execution Environment {{TEE}}.

## Requirements Notation

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in RFC
2119, BCP 14 {{RFC2119}}.

# TUDA Core Concept

There are significant differences between conventional bi-directional attestation and TUDA regarding both the information elements conveyed between Attestor and Verifier and the time-frame, in which an attestation can be considered to be fresh (and therefore trustworthy).

In general, remote attestation using a bi-directional communication scheme includes sending a nonce-challenge within a signed attestation token. Using the TPM 1.2 as an example, a corresponding nonce-challenge would be included within the signature created by the TPM_Quote command in order to prove the freshness of the attestation response, see e.g. {{PTS}}.

In contrast, the TUDA protocol uses the combined output of TPM_CertifyInfo and TPM_TickStampBlob. The former provides a proof about the platform's state by creating evidence that a certain key is bound to that state. The latter provides proof that the platform was in the specified state by using the bound key in a time operation. This combination enables a time-based attestation scheme. The approach is based on the concepts introduced in {{SCALE}} and {{SFKE2008}}.

Each TUDA IE has an individual time-frame, in which it is considered to be fresh (and therefore trustworthy). In consequence, each TUDA IE that composes data in motion is based on different methods of creation.

The freshness properties of a challenge-response based protocol define the point-of-time of attestation between:

* the time of transmission of the nonce, and
* the reception of the corresponding response.

Given the time-based attestation scheme, the freshness property of TUDA is equivalent to that of bi-directional challenge response attestation, if the point-in-time of attestation lies between:

* the transmission of a TUDA time-synchronization token, and
* the typical round-trip time between the Verifier and the Attestor.

The accuracy [FIXME IEEE PTP terminology ref] of this time-frame is defined by two factors: 

* the time-synchronization between the Attestor and the TSA. The time between the two tickstamps acquired via the hardware RoT define the scope of the maximum drift ("left" and "right" in respect to the timeline) to the TSA timestamp, and
* the drift of clocks included in the hardware RoT.

Since the conveyance of TUDA evidence does not rely upon a Verifier provided value (i.e. the nonce), the security guarantees of the protocol only incorporate the TSA and the hardware RoT. In consequence, TUDA evidence can even serve as proof of integrity in audit logs with precise point-in-time guarantees, in contrast to classical attestations.

{{rest}} contains guidance on how to utilize a REST architecture.

{{snmp}} contains guidance on how to create an SNMP binding and a corresponding TUDA-MIB.

{{yang}} contains a corresponding YANG module that supports both RESTCONF and CoMI.

{{tpm12}} contains a realization of TUDA using TPM 1.2 primitives.

{{tpm2}} contains a realization of TUDA using TPM 2.0 primitives.

# Terminology

This document introduces roles, information elements and types required to conduct TUDA and uses terminology (e.g. specific certificate names) typically seen in the context of attestation or hardware security modules.

## Universal Terms

Attestation Identity Key (AIK):

: a special purpose signature (therefore asymmetric) key that supports identity related operations. The private portion of the key pair is maintained confidential to the entity via appropriate measures (that have an impact on the scope of confidence). The public portion of the key pair may be included in AIK credentials that provide a claim about the entity.

Claim:

: A piece of information asserted about a subject {{RFC4949}}. A claim is represented as a name/value pair consisting of a Claim Name and a Claim Value {{-jwt}}.

: In the context of SACM, a claim is also specialized as an attribute/value pair that is intended to be related to a statement {{-sacmterm}}.

Endpoint Attestation:

: the creation of evidence on the Attestor that provides proof of a set of the endpoints's integrity measurements. This is done by digitally signing a set of PCRs using an AIK shielded by the hardware RoT.

Endpoint Characteristics:

: the context, composition, configuration, state, and behavior of an endpoint.

Evidence:

: a trustworthy set of claims about an endpoint's characteristics.

Identity:

: a set of claims that is intended to be related to an entity.

Integrity Measurements:

: Metrics of endpoint characteristics (i.e. composition, configuration and state) that 
affect the confidence in the trustworthiness of an endpoint. Digests of integrity measurements
can be stored in shielded locations (i.e. PCR of a TPM).

Reference Integrity Measurements:

: Signed measurements about the characteristics of an endpoint's characteristics that are provided by a vendor and are intended to be used as declarative guidance {{-sacmterm}} (e.g. a signed CoSWID).

Trustworthy:

: the qualities of an endpoint that guarantee a specific behavior and/or endpoint characteristics defined by declarative guidance.
Analogously, trustworthiness is the quality of being trustworthy with respect to declarative guidance.
Trustworthiness is not an absolute property but defined with respect to an entity, corresponding declarative guidance, and has a scope of confidence.

: Trustworthy Endpoint: an endpoint that guarantees trustworthy behavior and/or composition (with respect to certain declarative guidance and a scope of confidence).

: Trustworthy Statement: evidence that is trustworthy conveyed by an endpoint that is not necessarily trustworthy.

## Roles

Attestor:
: the endpoint that is the subject of the attestation to another endpoint.

Verifier:
: the endpoint that consumes the attestation of another endpoint to conduct a verification.

TSA:
: a Time Stamp Authority {{-timestamp}}

### General Types

Byte:
: the now customary synonym for octet

Cert:
: an X.509 certificate represented as a byte-string

### RoT specific terms

PCR:
: a Platform Configuration Register that is part of a hardware root of trust and is used to securely store and report measurements about security posture

PCR-Hash:
: a hash value of the security posture measurements stored in a TPM PCR (e.g. regarding running software instances) represented as a byte-string

## Certificates

TSA-CA:
: the Certificate Authority that provides the certificate for the TSA represented as a Cert

AIK-CA:
: the Certificate Authority that provides the certificate for the attestation identity key of the TPM. This is the client platform credential for this protocol. It is a placeholder for a specific CA and AIK-Cert is a placeholder for the corresponding certificate, depending on what protocol was used. The specific protocols are out of scope for this document, see also {{AIK-Enrollment}} and {{IEEE802.1AR}}.

# Time-Based Uni-Directional Attestation

A Time-Based Uni-Directional Attestation (TUDA) consists of the
following seven information elements. They are used to gain assurance of the Attestor's
platform configuration at a certain point in time:

TSA Certificate:

: The certificate of the Time Stamp Authority that is used in a subsequent synchronization
  protocol token. This certificate is signed by the TSA-CA.

AIK Certificate:

: A certificate about the Attestation Identity Key (AIK) used. This may or may not
  also be an {{IEEE802.1AR}} IDevID or LDevID, depending on their setting of the corresponding identity property.
  ({{AIK-Credential}}, {{AIK-Enrollment}}; see {{aik}}.)

Synchronization Token:

: The reference for attestations are the relative timestanps provided by the hardware RoT. In
  order to put attestations into relation with a Real Time Clock
  (RTC), it is necessary to provide a cryptographic synchronization
  between these trusted relative timestamps and the regular RTC that is a hardware component of the Attestor. To do so, a synchronization
  protocol is run with a Time Stamp Authority (TSA).

Restriction Info:

: The attestation relies on the capability of the hardware RoT to operate on restricted keys.
  Whenever the PCR values for the machine to be attested change, a new restricted key
  is created that can only be operated as long as the PCRs remain in their current state.

: In order to prove to the Verifier that this restricted temporary key actually has
  these properties and also to provide the PCR value that it is restricted, the corresponding
  signing capabilities of the hardware RoT are used. It creates a signed certificate using the AIK about
  the newly created restricted key.

Measurement Log:

: Similarly to regular attestations, the Verifier needs a way to reconstruct the PCRs'
  values in order to estimate the trustworthiness of the device. As such, a list of
  those elements that were extended into the PCRs is reported. Note though that for
  certain environments, this step may be optional if a list of valid PCR configurations
  (in the form of RIM available to the Verifier) exists and no measurement log is required.

Implicit Attestation:

: The actual attestation is then based upon a signed timestamp provided by the hardware RoT using the restricted
  temporary key that was certified in the steps above. The signed timestamp provides evidence that at this point in time (with respect to the relative time of the hardware RoT)
  a certain configuration existed (namely the PCR values associated
  with the restricted key). Together with the synchronization token this timestamp represented in relative time
  can then be related to the real-time clock.

Concise SWID tags:

: As an option to better assess the trustworthiness of an Attestor, a Verifier can request the
  reference hashes (RIM, which are often referred to as golden measurements) of all started software components
  to compare them with the entries in the measurement log. References hashes regarding installed
  (and therefore running) software can be provided by the manufacturer via SWID tags. SWID tags are
  provided by the Attestor using the Concise SWID representation {{-coswid}} and bundled into a CBOR array (a RIM Manifest). 
  Ideally, the reference hashes include a signature created by the manufacturer of the software to prove their integrity.


These information elements could be sent en bloc, but it is recommended 
to retrieve them separately to save bandwidth, since these
elements have different update cycles. In most cases, retransmitting
all seven information elements would result in unnecessary redundancy.

Furthermore, in some scenarios it might be feasible not to store all
elements on the Attestor endpoint, but instead they could be retrieved
from another location or be pre-deployed to the Verifier.
It is also feasible to only store public keys on the Verifier and skip the whole
certificate provisioning completely in order to save bandwidth and computation
time for certificate verification.

## TUDA Information Elements Update Cycles {#updatecycles}

An endpoint can be in various states and have various information associated
 with it during its life cycle. For TUDA, a subset of the states 
(which can include associated information) that an endpoint and its hardware root of trust can be in, is
 important to the attestation process. States can be:

* persistent, even after a hard reboot. This includes certificates
  that are associated with the endpoint itself or with services it relies on.

* volatile to a degree, because they change at the beginning of each boot cycle.
  This includes the capability of a hardware RoT to provide relative time which provides the basis for the
  synchronization token and implicit attestation---and which can reset after an endpoint is powered off.

* very volatile, because they change during an uptime cycle
  (the period of time an endpoint is powered on, starting with its boot).
  This includes the content of PCRs of a hardware RoT and thereby also the PCR-restricted signing 
  keys used for attestation.

Depending on this "lifetime of state", data has to be transported over the wire,
 or not. E.g. information that does not change due to a reboot typically
 has to be transported only once between the Attestor and the Verifier.

There are three kinds of events that require a renewed attestation:

* The Attestor completes a boot-cycle
* A relevant PCR changes
* Too much time has passed since the last attestation statement

The third event listed above is variable per application use case and also depends on the precision of the clock included in the hardware RoT.
For usage scenarios, in which the device would periodically
push information to be used in an audit-log, a time-frame of approximately one update
per minute should be sufficient in most cases. For those usage scenarios, where
Verifiers request (pull) a fresh attestation statement, an implementation could use the hardware RoT
continuously to always present the most freshly created results. To save some
utilization of the hardware RoT for other purposes, however, a time-frame of once per ten
seconds is recommended, which would typically leave about 80% of utilization for other applications.

<!--

AIK-Token only once for the lifetime

Sync-Token only once per boot-cycle. Or when clock-drift gets too big

CertifyInfo whenever PCRs change, since new key gets created

MeasurementLog whenever PCRs have changed in order to validate new PCRs

Implicit Attestation for each time that an attestation is needed

-->

~~~~~~~~~~~
Attestor                                                 Verifier
   |                                                         |
 Boot                                                        |
   |                                                         |
 Create Sync-Token                                           |
   |                                                         |
 Create Restricted Key                                       |
 Certify Restricted Key                                      |
   |                                                         |
   | AIK-Cert ---------------------------------------------> |
   | Sync-Token -------------------------------------------> |
   | Certify-Info -----------------------------------------> |
   | Measurement Log --------------------------------------> |
   | Attestation ------------------------------------------> |
   |                                           Verify Attestation
   |                                                         |
   |       <Time Passed>                                     |
   |                                                         |
   | Attestation ------------------------------------------> |
   |                                           Verify Attestation
   |                                                         |
   |       <Time Passed>                                     |
   |                                                         |
 PCR-Change                                                  |
   |                                                         |
 Create Restricted Key                                       |
 Certify Restricted Key                                      |
   |                                                         |
   | Certify-Info -----------------------------------------> |
   | Measurement Log --------------------------------------> |
   | Attestation ------------------------------------------> |
   |                                           Verify Attestation
   |                                                         |
 Boot                                                        |
   |                                                         |
 Create Sync-Token                                           |
   |                                                         |
 Create Restricted Key                                       |
 Certify Restricted Key                                      |
   |                                                         |
   | Sync-Token -------------------------------------------> |
   | Certify-Info -----------------------------------------> |
   | Measurement Log --------------------------------------> |
   | Attestation ------------------------------------------> |
   |                                           Verify Attestation
   |                                                         |
   |       <Time Passed>                                     |
   |                                                         |
   | Attestation ------------------------------------------> |
   |                                           Verify Attestation
   |                                                         |
~~~~~~~~~~~
{: #SequenceExample title="Example sequence of events"}

#  Sync Base Protocol

The uni-directional approach of TUDA requires evidence on how the TPM time represented in ticks (relative time since boot of the TPM) relates to the standard time provided by the TSA.
The Sync Base Protocol (SBP) creates evidence that binds the TPM tick time to the TSA timestamp. The binding information is used by and conveyed via the Sync Token (TUDA IE). There are three actions required to create the content of a Sync Token:

* At a given point in time (called "left"), a signed tickstamp counter value is acquired from the hardware RoT. The hash of counter and signature is used as a nonce in the request directed at the TSA.
* The corresponding response includes a data-structure incorporating the trusted timestamp token and its signature created by the TSA.
* At the point-in-time the response arrives (called "right"), a signed tickstamp counter value is acquired from the hardware RoT again, using a hash of the signed TSA timestamp as a nonce.

The three time-related values --- the relative timestamps provided by the hardware RoT ("left" and "right") and the TSA timestamp --- and their corresponding signatures are aggregated in order to create a corresponding Sync Token to be used as a TUDA Information Element that can be conveyed as evidence to a Verifier.

The drift of a clock incorporated in the hardware RoT that drives the increments of the tick counter constitutes one of the triggers that can initiate a TUDA Information Element Update Cycle in respect to the freshness of the available Sync Token. 

<!-- The following functions illustrate the worst case freshness-window assuming the maximum drift of TPM tick counters that is considered acceptable in respect to the standard time - 15 percent - as defined by the TPM specification: -->

content TBD

#  IANA Considerations {#iana}

This memo includes requests to IANA, including registrations for media
type definitions.

TBD


#  Security Considerations

There are Security Considerations. TBD


#  Change Log

Changes from version 04 to I2NSF related document version 00:
* Refactored main document to be more technology agnostic
* Added first draft of procedures for TPM 2.0
* Improved content consistency and structure of all sections

Changes from version 03 to version 04:

* Refactoring of Introduction, intend, scope and audience
* Added first draft of Sync Base Prootoll section illustrated background for interaction with TSA
* Added YANG module
* Added missing changelog entry

Changes from version 02 to version 03:

* Moved base concept out of Introduction
* First refactoring of Introduction and Concept
* First restructuring of Appendices and improved references

Changes from version 01 to version 02:

* Restructuring of Introduction, highlighting conceptual prerequisites
* Restructuring of Concept to better illustrate differences to hand-shake based attestation and deciding factors regarding freshness properties
* Subsection structure added to Terminology
* Clarification of descriptions of approach (these were the FIXMEs)
* Correction of RestrictionInfo structure: Added missing signature member

Changes from version 00 to version 01:

Major update to the SNMP MIB and added a table for the Concise SWID profile Reference Hashes that provides additional information to be compared with the measurement logs.

# Contributors

TBD

--- back

# REST Realization {#rest}

Each of the seven data items is defined as a media type ({{iana}}).
Representations of resources for each of these media types can be
retrieved from URIs that are defined by the respective servers {{-lawn}}.
As can be derived from the URI, the actual retrieval is via one of the HTTPs
({{-http1}}, {{-http2}}) or CoAP {{-coap}}.  How a client obtains
these URIs is dependent on the application; e.g., CoRE Web links {{-link}}
can be used to obtain the relevant URIs from the self-description of a
server, or they could be prescribed by a RESTCONF data model {{-restconf}}.

# SNMP Realization {#snmp}

SNMPv3 [STD62] {{RFC3411}} is widely available on computers and also constrained devices.
To transport the TUDA information elements, an SNMP MIB is defined below which
encodes each of the seven TUDA information elements into a table.  Each row in a
table contains a single read-only columnar SNMP object of datatype OCTET-STRING.
The values of a set of rows in each table can be concatenated to reconstitute a
CBOR-encoded TUDA information element.  The Verifier can retrieve the values for
each CBOR fragment by using SNMP GetNext requests to "walk" each table and can
decode each of the CBOR-encoded data items based on the corresponding CDDL {{-cddl}}
definition.

Design Principles:

1. Over time, TUDA attestation values age and should no longer be used.  Every
   table in the TUDA MIB has a primary index with the value of a separate
   scalar cycle counter object that disambiguates the transition from one
   attestation cycle to the next.

2. Over time, the measurement log information (for example) may grow
   large. Therefore, read-only cycle counter scalar objects in all TUDA MIB object
   groups facilitate more efficient access with SNMP GetNext requests.

3. Notifications are supported by an SNMP trap definition with all of the cycle
   counters as bindings, to alert a Verifier that a new attestation cycle has 
   occurred (e.g., synchronization data, measurement log, etc. have been updated
   by adding new rows and possibly deleting old rows).  

## Structure of TUDA MIB

The following table summarizes the object groups, tables and their indexes, and conformance requirements for the TUDA MIB:

~~~~~~~~~~
|-------------|-------|----------|----------|----------|
| Group/Table | Cycle | Instance | Fragment | Required |
|-------------|-------|----------|----------|----------|
| General     |       |          |          | x        |
| AIKCert     | x     | x        | x        |          |
| TSACert     | x     | x        | x        |          |
| SyncToken   | x     |          | x        | x        |
| Restrict    | x     |          |          | x        |
| Measure     | x     | x        |          |          |
| VerifyToken | x     |          |          | x        |
| SWIDTag     | x     | x        | x        |          |
|-------------|-------|----------|----------|----------|
~~~~~~~~~~

### Cycle Index

A tudaV1\<Group\>CycleIndex is the:

1. first index of a row (element instance or element fragment) in the
tudaV1\<Group\>Table;  
1. identifier of an update cycle on the table, when rows were added and/or
deleted from the table (bounded by tudaV1\<Group\>Cycles); and  
1. binding in the tudaV1TrapV2Cycles notification for directed polling.


### Instance Index

A tudaV1\<Group\>InstanceIndex is the:

1. second index of a row (element instance or element fragment) in the
tudaV1\<Group\>Table; except for 
1. a row in the tudaV1SyncTokenTable (that has only one instance per cycle).


### Fragment Index

A tudaV1\<Group\>FragmentIndex is the:

1. last index of a row (always an element fragment) in the
tudaV1\<Group\>Table; and
1. accomodation for SNMP transport mapping restrictions for large string
elements that require fragmentation.  

## Relationship to Host Resources MIB

The General group in the TUDA MIB is analogous to the System group in the
Host Resources MIB [RFC2790] and provides context information for the TUDA
attestation process.  

The Verify Token group in the TUDA MIB is analogous to the Device group in
the Host MIB and represents the verifiable state of a TPM device and its
associated system.  

The SWID Tag group (containing a Concise SWID reference hash profile {{-coswid}}) in the TUDA MIB is analogous to the Software Installed and
Software Running groups in the Host Resources MIB [RFC2790].


## Relationship to Entity MIB

The General group in the TUDA MIB is analogous to the Entity General group in
the Entity MIB v4 [RFC6933] and provides context information for the TUDA
attestation process.  

The SWID Tag group in the TUDA MIB is analogous to the Entity Logical group
in the Entity MIB v4 [RFC6933].  


## Relationship to Other MIBs

The General group in the TUDA MIB is analogous to the System group in MIB-II
[RFC1213] and the System group in the SNMPv2 MIB [RFC3418] and provides
context information for the TUDA attestation process.  

## Definition of TUDA MIB

~~~~ SMIv2
<CODE BEGINS>
{::include ietf-tuda.mib}
<CODE ENDS>
~~~~

# YANG Realization {#yang}

~~~~ YANG
<CODE BEGINS>
{::include TUDA-V1-ATTESTATION-MIB.yang}
<CODE ENDS>
~~~~

# Realization with TPM functions

## TPM Functions

The following TPM structures, resources and functions are used within this approach.
They are based upon the TPM specifications {{TPM12}} and {{TPM2}}.

### Tick-Session and Tick-Stamp

On every boot, the TPM initializes a new Tick-Session. Such a tick-session consists
of a nonce that is randomly created upon each boot to identify the current boot-cycle
-- the phase between boot-time of the device and shutdown or power-off --
and prevent replaying of old tick-session values. The TPM uses its internal entropy
source that guarantees virtually no collisions of the nonce values between two of such
boot cycles.

It further includes an internal timer that is being initialize to Zero on each
reboot. From this point on, the TPM increments this timer continuously based upon its
internal secure clocking information until the device is powered down or set to sleep.
By its hardware design, the TPM will detect attacks on any of those properties.

The TPM offers the function TPM_TickStampBlob, which allows the TPM to create a signature
over the current tick-session and two externally provided input values. These input values
are designed to serve as a nonce and as payload data to be included in a TickStampBlob:
TickstampBlob := sig(TPM-key, currentTicks || nonce || externalData).

As a result,
one is able to proof that at a certain point in time (relative to the tick-session)
after the provisioning of a certain nonce, some certain externalData was known and
provided to the TPM. If an approach however requires no input values or only one
input value (such as the use in this document) the input values can be set to well-known
value. The convention used within TCG specifications and within this document is to
use twenty bytes of zero h'0000000000000000000000000000000000000000' as well-known
value.


### Platform Configuration Registers (PCRs)

The TPM is a secure cryptoprocessor that provides the ability to store measurements
and metrics about an endpoint's configuration and state in a secure, tamper-proof
environment. Each of these security relevant metrics can be stored in a volatile
Platform Configuration Register (PCR) inside the TPM. These measurements can be
conducted at any point in time, ranging from an initial BIOS boot-up sequence to
measurements taken after hundreds of hours of uptime.

The initial measurement is triggered by the Platforms so-called pre-BIOS or ROM-code.
It will conduct a measurement of the first loadable pieces of code; i.e.\ the BIOS.
The BIOS will in turn measure its Option ROMs and the BootLoader, which measures the
OS-Kernel, which in turn measures its applications. This describes a so-called measurement
chain. This typically gets recorded in a so-called measurement log, such that the
values of the PCRs can be reconstructed from the individual measurements for validation.

Via its PCRs, a TPM provides a Root of Trust that can, for example, support secure
boot or remote attestation. The attestation of an endpoint's identity or security
posture is based on the content of an TPM's PCRs (platform integrity measurements).


### PCR restricted Keys

Every key inside the TPM can be restricted in such a way that it can only be used
if a certain set of PCRs are in a predetermined state. For key creation the desired
state for PCRs are defined via the PCRInfo field inside the keyInfo parameter.
Whenever an operation using this key is performed, the TPM first checks whether
the PCRs are in the correct state. Otherwise the operation is denied by the TPM.

### CertifyInfo

The TPM offers a command to certify the properties of a key by means of a signature
using another key. This includes especially the keyInfo which in turn includes the PCRInfo information
used during key creation. This way, a third party can be assured about the fact that
a key is only usable if the PCRs are in a certain state.

## IE Generation Procedures for TPM 1.2 {#tpm12} 

### AIK and AIK Certificate {#aik}

Attestations are based upon a cryptographic signature performed by the TPM using
a so-called Attestation Identity Key (AIK). An AIK has the properties that it cannot
be exported from a TPM and is used for attestations. Trust in the AIK is established
by an X.509 Certificate emitted by a Certificate Authority. The AIK certificate is
either provided directly or via a so-called PrivacyCA {{AIK-Enrollment}}.

This element consists of the AIK certificate that includes the AIK's public key used
during verification as well as the certificate chain up to the Root CA for validation
of the AIK certificate itself.

~~~~ CDDL
TUDA-Cert = [AIK-Cert, TSA-Cert]; maybe split into two for SNMP
AIK-Cert = Cert
TSA-Cert = Cert
~~~~
{:cddl #cert-token title="TUDA-Cert element in CDDL"}

The TSA-Cert is a standard certificate of the TSA.

The AIK-Cert may be provisioned in a secure environment using standard means or
it may follow the PrivacyCA protocols. {{make-cert-token}} gives a rough sketch
of this protocol. See {{AIK-Enrollment}} for more information.

The X.509 Certificate is built from the AIK public key and the
corresponding PKCS #7 certificate chain, as shown in
{{make-cert-token}}.

Required TPM functions:

~~~~ pseudocode
| create_AIK_Cert(...) = {
|   AIK = TPM_MakeIdentity()
|   IdReq = CollateIdentityRequest(AIK,EK)
|   IdRes = Call(AIK-CA, IdReq)
|   AIK-Cert = TPM_ActivateIdentity(AIK, IdRes)
| }
|
| /* Alternative */
|
| create_AIK_Cert(...) = {
|   AIK = TPM_CreateWrapKey(Identity)
|   AIK-Cert = Call(AIK-CA, AIK.pubkey)
| }
~~~~
{: #make-cert-token title="Creating the TUDA-Cert element"}

### Synchronization Token

The reference for Attestations are the Tick-Sessions of the TPM. In order to put Attestations
into relation with a Real Time Clock (RTC), it is necessary to provide a cryptographic
synchronization between the tick session and the RTC. To do so, a synchronization
protocol is run with a Time Stamp Authority (TSA) that consists of three steps:

- The TPM creates a TickStampBlob using the AIK
- This TickstampBlob is used as nonce to the Timestamp of the TSA
- Another TickStampBlob with the AIK is created using the TSA's Timestamp a nonce

The first TickStampBlob is called "left" and the second "right" in a reference to
their position on a time-axis.

These three elements, with the TSA's certificate factored out, form
the synchronization token

~~~~ CDDL
TUDA-Synctoken = [
  left: TickStampBlob-Output,
  timestamp: TimeStampToken,
  right: TickStampBlob-Output,
]

TimeStampToken = bytes ; RFC 3161

TickStampBlob-Output = [
  currentTicks: TPM-CURRENT-TICKS,
  sig: bytes,
]

TPM-CURRENT-TICKS = [
  currentTicks: uint
  ? (
    tickRate: uint
    tickNonce: TPM-NONCE
  )
]
; Note that TickStampBlob-Output "right" can omit the values for
;   tickRate and tickNonce since they are the same as in "left"

TPM-NONCE = bytes .size 20
~~~~
{:cddl #sync-token title="TUDA-Sync element in CDDL"}

Required TPM functions:

<!-- TPM_TickStampBlob: -->
<!-- : explain various inputs and applications -->

~~~~ pseudocode
| dummyDigest = h'0000000000000000000000000000000000000000'
| dummyNonce = dummyDigest
|
| create_sync_token(AIKHandle, TSA) = {
|   ts_left = TPM_TickStampBlob(
|       keyHandle = AIK_Handle,      /*TPM_KEY_HANDLE*/
|       antiReplay = dummyNonce,     /*TPM_NONCE*/
|       digestToStamp = dummyDigest  /*TPM_DIGEST*/)
|
|   ts = TSA_Timestamp(TSA, nonce = hash(ts_left))
|
|   ts_right = TPM_TickStampBlob(
|       keyHandle = AIK_Handle,      /*TPM_KEY_HANDLE*/
|       antiReplay = dummyNonce,     /*TPM_NONCE*/
|       digestToStamp = hash(ts))    /*TPM_DIGEST*/
|
|   TUDA-SyncToken = [[ts_left.ticks, ts_left.sig], ts,
|                     [ts_right.ticks.currentTicks, ts_right.sig]]
|   /* Note: skip the nonce and tickRate field for ts_right.ticks */
| }

~~~~
{: #make-sync-token title="Creating the Sync-Token element"}


### RestrictionInfo

The attestation relies on the capability of the TPM to operate on restricted keys.
Whenever the PCR values for the machine to be attested change, a new restricted key
is created that can only be operated as long as the PCRs remain in their current state.

In order to prove to the Verifier that this restricted temporary key actually has
these properties and also to provide the PCR value that it is restricted, the TPM
command TPM_CertifyInfo is used. It creates a signed certificate using the AIK about
the newly created restricted key.

This token is formed from the list of:

- PCR list,
- the newly created restricted public key, and
- the certificate.

~~~~ CDDL
TUDA-RestrictionInfo = [Composite,
                        restrictedKey_Pub: Pubkey,
                        CertifyInfo]

PCRSelection = bytes .size (2..4) ; used as bit string

Composite = [
  bitmask: PCRSelection,
  values: [*PCR-Hash],
]

Pubkey = bytes ; may be extended to COSE pubkeys

CertifyInfo = [
  TPM-CERTIFY-INFO,
  sig: bytes,
]

TPM-CERTIFY-INFO = [
  ; we don't encode TPM-STRUCT-VER:
  ; these are 4 bytes always equal to h'01010000'
  keyUsage: uint, ; 4byte? 2byte?
  keyFlags: bytes .size 4, ; 4byte
  authDataUsage: uint, ; 1byte (enum)
  algorithmParms: TPM-KEY-PARMS,
  pubkeyDigest: Hash,
  ; we don't encode TPM-NONCE data, which is 20 bytes, all zero
  parentPCRStatus: bool,
  ; no need to encode pcrinfosize
  pcrinfo: TPM-PCR-INFO,        ; we have exactly one
]

TPM-PCR-INFO = [
    pcrSelection: PCRSelection; /* TPM_PCR_SELECTION */
    digestAtRelease: PCR-Hash;  /* TPM_COMPOSITE_HASH */
    digestAtCreation: PCR-Hash; /* TPM_COMPOSITE_HASH */
]

TPM-KEY-PARMS = [
  ; algorithmID: uint, ; <= 4 bytes -- not encoded, constant for TPM1.2
  encScheme: uint, ; <= 2 bytes
  sigScheme: uint, ; <= 2 bytes
  parms: TPM-RSA-KEY-PARMS,
]

TPM-RSA-KEY-PARMS = [
  ; "size of the RSA key in bits":
  keyLength: uint
  ; "number of prime factors used by this RSA key":
  numPrimes: uint
  ; "This SHALL be the size of the exponent":
  exponentSize: null / uint / biguint
  ; "If the key is using the default exponent then the exponentSize
  ; MUST be 0" -> we represent this case as null
]

~~~~
{:cddl #key-token title="TUDA-Key element in CDDL"}


Required TPM functions:

~~~~ pseudocode
| dummyDigest = h'0000000000000000000000000000000000000000'
| dummyNonce = dummyDigest
|
| create_Composite
|
| create_restrictedKey_Pub(pcrsel) = {
|   PCRInfo = {pcrSelection = pcrsel,
|              digestAtRelease = hash(currentValues(pcrSelection))
|              digestAtCreation = dummyDigest}
|   / * PCRInfo is a TPM_PCR_INFO and thus also a TPM_KEY */
|
|   wk = TPM_CreateWrapKey(keyInfo = PCRInfo)
|   wk.keyInfo.pubKey
| }
|
| create_TPM-Certify-Info = {
|   CertifyInfo = TPM_CertifyKey(
|       certHandle = AIK,          /* TPM_KEY_HANDLE */
|       keyHandle = wk,            /* TPM_KEY_HANDLE */
|       antiReply = dummyNonce)    /* TPM_NONCE */
|
|   CertifyInfo.strip()
|   /* Remove those values that are not needed */
| }
~~~~
{: #make-pubkey title="Creating the pubkey"}


### Measurement Log {#mlog}

Similarly to regular attestations, the Verifier needs a way to reconstruct the PCRs'
values in order to estimate the trustworthiness of the device. As such, a list of
those elements that were extended into the PCRs is reported. Note though that for
certain environments, this step may be optional if a list of valid PCR configurations
exists and no measurement log is required.

~~~~ CDDL
TUDA-Measurement-Log = [*PCR-Event]
PCR-Event = [
  type: PCR-Event-Type,
  pcr: uint,
  template-hash: PCR-Hash,
  filedata-hash: tagged-hash,
  pathname: text; called filename-hint in ima (non-ng)
]

PCR-Event-Type = &(
  bios: 0
  ima: 1
  ima-ng: 2
)

; might want to make use of COSE registry here
; however, that might never define a value for sha1
tagged-hash /= [sha1: 0, bytes .size 20]
tagged-hash /= [sha256: 1, bytes .size 32]
~~~~

### Implicit Attestation {#impa}

The actual attestation is then based upon a TickStampBlob using the restricted
temporary key that was certified in the steps above. The TPM-Tickstamp is executed
and thereby provides evidence that at this point in time (with respect to the TPM
internal tick-session) a certain configuration existed (namely the PCR values associated
with the restricted key). Together with the synchronization token this tick-related
timing can then be related to the real-time clock.

This element consists only of the TPM_TickStampBlock with no nonce.

~~~~ CDDL
TUDA-Verifytoken = TickStampBlob-Output
~~~~
{:cddl #verify-token title="TUDA-Verify element in CDDL"}

Required TPM functions:

~~~~ pseudocode
| imp_att = TPM_TickStampBlob(
|     keyHandle = restrictedKey_Handle,     /*TPM_KEY_HANDLE*/
|     antiReplay = dummyNonce,              /*TPM_NONCE*/
|     digestToStamp = dummyDigest)          /*TPM_DIGEST*/
|
| VerifyToken = imp_att
~~~~
{: #make-verifytoken title="Creating the Verify Token"}


### Attestation Verification Approach

The seven TUDA information elements transport the essential content that is required to enable
verification of the attestation statement at the Verifier. The following listings illustrate
the verification algorithm to be used at the Verifier in
pseudocode. The pseudocode provided covers the entire verification
task.
If only a subset of TUDA elements changed (see {{updatecycles}}), only
the corresponding code listings need to be re-executed.

~~~~ pseudocode
| TSA_pub = verifyCert(TSA-CA, Cert.TSA-Cert)
| AIK_pub = verifyCert(AIK-CA, Cert.AIK-Cert)
~~~~
{: #verify-Certs title="Verification of Certificates"}


~~~~ pseudocode
| ts_left = Synctoken.left
| ts_right = Synctoken.right
|
| /* Reconstruct ts_right's omitted values; Alternatively assert == */
| ts_right.currentTicks.tickRate = ts_left.currentTicks.tickRate
| ts_right.currentTicks.tickNonce = ts_left.currentTicks.tickNonce
|
| ticks_left = ts_left.currentTicks
| ticks_right = ts_right.currentTicks
|
| /* Verify Signatures */
| verifySig(AIK_pub, dummyNonce || dummyDigest || ticks_left)
| verifySig(TSA_pub, hash(ts_left) || timestamp.time)
| verifySig(AIK_pub, dummyNonce || hash(timestamp) || ticks_right)
|
| delta_left = timestamp.time -
|     ticks_left.currentTicks * ticks_left.tickRate / 1000
|
| delta_right = timestamp.time -
|     ticks_right.currentTicks * ticks_right.tickRate / 1000
~~~~
{: #verify-sync title="Verification of Synchronization Token"}


~~~~ pseudocode
| compositeHash = hash_init()
| for value in Composite.values:
|     hash_update(compositeHash, value)
| compositeHash = hash_finish(compositeHash)
|
| certInfo = reconstruct_static(TPM-CERTIFY-INFO)
|
| assert(Composite.bitmask == ExpectedPCRBitmask)
| assert(certInfo.pcrinfo.PCRSelection == Composite.bitmask)
| assert(certInfo.pcrinfo.digestAtRelease == compositeHash)
| assert(certInfo.pubkeyDigest == hash(restrictedKey_Pub))
|
| verifySig(AIK_pub, dummyNonce || certInfo)
~~~~
{: #verify-restrictioninfo title="Verification of Restriction Info"}


~~~~ pseudocode
| for event in Measurement-Log:
|     if event.pcr not in ExpectedPCRBitmask:
|         continue
|     if event.type == BIOS:
|         assert_whitelist-bios(event.pcr, event.template-hash)
|     if event.type == ima:
|         assert(event.pcr == 10)
|         assert_whitelist(event.pathname, event.filedata-hash)
|         assert(event.template-hash == 
|                hash(event.pathname || event.filedata-hash))
|     if event.type == ima-ng:
|         assert(event.pcr == 10)
|         assert_whitelist-ng(event.pathname, event.filedata-hash)
|         assert(event.template-hash ==
|                hash(event.pathname || event.filedata-hash))
|
|     virtPCR[event.pcr] = hash_extend(virtPCR[event.pcr], 
|                                      event.template-hash)
|
| for pcr in ExpectedPCRBitmask:
|     assert(virtPCR[pcr] == Composite.values[i++]
~~~~
{: #verify-measurementlog title="Verification of Measurement Log"}


~~~~ pseudocode
| ts = Verifytoken
|
| /* Reconstruct ts's omitted values; Alternatively assert == */
| ts.currentTicks.tickRate = ts_left.currentTicks.tickRate
| ts.currentTicks.tickNonce = ts_left.currentTicks.tickNonce
|
| verifySig(restrictedKey_pub, dummyNonce || dummyDigest || ts)
|
| ticks = ts.currentTicks
|
| time_left = delta_right + ticks.currentTicks * ticks.tickRate / 1000
| time_right = delta_left + ticks.currentTicks * ticks.tickRate / 1000
|
| [time_left, time_right]
~~~~
{: #verify-attestation title="Verification of Attestation Token"}

## IE Generation Procedures for TPM 2.0 {#tpm2}

The pseudo code below includes general operations that are conducted as specific TPM commands:

* hash() : description TBD
* sig() : description TBD
* X.509-Certificate() : description TBD

These represent the output structure of that command in the form of a byte string value.

### AIK and AIK Certificate {#aik2}

Attestations are based upon a cryptographic signature performed by the TPM using
a so-called Attestation Identity Key (AIK). An AIK has the properties that it cannot
be exported from a TPM and is used for attestations. Trust in the AIK is established
by an X.509 Certificate emitted by a Certificate Authority. The AIK certificate is
either provided directly or via a so-called PrivacyCA {{AIK-Enrollment}}.

This element consists of the AIK certificate that includes the AIK's public key used
during verification as well as the certificate chain up to the Root CA for validation
of the AIK certificate itself.

~~~~ pseudo
TUDA-Cert = [AIK-Cert, TSA-Cert]; maybe split into two for SNMP
AIK-Certificate = X.509-Certificate(AIK-Key,Restricted-Flag)
TSA-Certificate = X.509-Certificate(TSA-Key, TSA-Flag)
~~~~
{:pseudo #cert-token2 title="TUDA-Cert element for TPM 2.0"}

### Synchronization Token

The synchronization token uses a different TPM command, TPM2 GetTime() instead of TPM TickStampBlob().  The TPM2 GetTime() command contains the clock and time information of the TPM. The clock information is the equivalent of TUDA v1's tickSession information.

~~~~ pseudo
TUDA-SyncToken = [
  left_GetTime = sig(AIK-Key,
                     TimeInfo = [
                       time,
                       resetCount,
                       restartCount
                     ]
                    ),
  middle_TimeStamp = sig(TSA-Key,
                         hash(left_TickStampBlob),
                         UTC-localtime
                        ),
  right_TickStampBlob = sig(AIK-Key,
                            hash(middle_TimeStamp),
                            TimeInfo = [
                              time,
                              resetCount,
                              restartCount
                            ]
                           )
]
~~~~
{:pseudo #sync-token2 title="TUDA-Sync element for TPM 2.0"}

### Measurement Log

The creation procedure is identical to {mlog}.

~~~~ pseudo
Measurement-Log = [ 
  * [ EventName,
      PCR-Num,
      Event-Hash ]
]
~~~~
{:pseudo #log-token2 title="TUDA-Log element for TPM 2.0"}

### Explicit time-based Attestation

The TUDA attestation token consists of the result of TPM2_Quote() or a set of TPM2_PCR_READ followed by a TPM2_GetSessionAuditDigest. It proves that --- at a certain point-in-time with respect to the TPM's internal clock --- a certain configuration of PCRs was present, as denoted in the keys restriction information.

~~~~ pseudo
TUDA-AttestationToken = TUDA-AttestationToken_quote / TUDA-AttestationToken_audit

TUDA-AttestationToken_quote = sig(AIK-Key,
                                  TimeInfo = [
                                    time,
                                    resetCount,
                                    restartCount
                                  ],
                                  PCR-Selection = [ * PCR],
                                  PCR-Digest := PCRDigest
                                 )

TUDA-AttestationToken_audit = sig(AIK-key,
                                  TimeInfo = [
                                    time,
                                    resetCount,
                                    restartCount
                                  ],
                                  Session-Digest := PCRDigest
                                 )
~~~~
{:pseudo #attest-token2 title="TUDA-Attest element for TPM 2.0"}

### Sync Proof

In order to proof to the Verifier that the TPM's clock was not 'fast-forwarded' the result of a TPM2_GetTime() is sent after the TUDA-AttestationToken.

~~~~ pseudo
TUDA-SyncProof = sig(AIK-Key,
                     TimeInfo = [
                       time,
                       resetCount,
                       restartCount
                     ]
                    ),
~~~~
{:pseudo #prrof-token2 title="TUDA-Proof element for TPM 2.0"}

#  Acknowledgements
{: numbered="no"}

<!--  LocalWords:  TPM AIK TUDA uptime PCR Verifier Attestor CoRE RTC
 -->
<!--  LocalWords:  RESTCONF pseudocode disambiguates TSA PCRs
 -->
<!--  LocalWords:  Attestor's retransmitting Verifiers Timestamp
 -->
<!--  LocalWords:  TickStampBlob
 -->
