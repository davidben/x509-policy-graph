---
title: Updates to X.509 Policy Validation
abbrev: Updates to X.509 Policy Validation
docname: draft-ietf-lamps-x509-policy-graph-latest
category: std
submissionType: IETF

updates: 5280

ipr: trust200902
area: "Security"
keyword: Internet-Draft
workgroup: "Limited Additional Mechanisms for PKIX and SMIME"

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: "D. Benjamin"
    name: "David Benjamin"
    organization: "Google LLC"
    email: davidben@google.com

informative:
  X.509:
    title: >
      Information technology - Open Systems
      Interconnection - The Directory: Public-key and
      attribute certificate frameworks
    author:
      org: International Telecommunications Union
    date: October 2019
    seriesinfo:
      ITU-T: Recommendation X.509

  CVE-2023-0464:
    title: Excessive Resource Usage Verifying X.509 Policy Constraints
    target: https://www.cve.org/CVERecord?id=CVE-2023-0464
    date: March 2023

  CVE-2023-23524:
    title: Processing a maliciously crafted certificate may lead to a denial-of-service
    target: https://www.cve.org/CVERecord?id=CVE-2023-23524
    date: February 2023

  BoringSSL:
    title: BoringSSL
    target: https://boringssl.googlesource.com/boringssl
    date: January 2024

  LibreSSL:
    title: LibreSSL
    target: https://www.libressl.org/
    date: January 2024

--- abstract

This document updates RFC 5280 to replace the algorithm for X.509 policy
validation with an equivalent, more efficient algorithm. The original algorithm
built a structure which scaled exponentially in the worst case, leaving
implementations vulnerable to denial-of-service attacks.

--- middle

# Introduction

{{!RFC5280}} defines a suite of extensions for determining the "policies" which
apply to a certification path. A policy is described by an object identifier
(OID), and a set of optional qualifiers.

Policy validation in {{RFC5280}} is complex. As an overview, the certificate
policies extension ({{Section 4.2.1.4 of !RFC5280}}) describes the policies,
with optional qualifiers, under which an individual certificate was issued.
The policy mappings extension ({{Section 4.2.1.5 of !RFC5280}}) allows a
CA certificate to map its policy OIDs to other policy OIDs in certificates
that it issues. Subject to these mappings and other extensions, the certification
path's overall policy set is the intersection of policies asserted by each
certificate in the path, collecting the corresponding qualifiers.

The procedure in {{Section 6.1 of !RFC5280}} determines this set in the course
of certification path validation. It does so by building a policy tree,
containing policies asserted by each certificate and mappings between
them. This tree can grow exponentially in the depth of the certification path,
which means an attacker, with a small input, can cause a path validator to
consume excessive memory and computational resources. This cost asymmetry
can lead to a denial-of-service vulnerability in X.509-based applications, such
as {{CVE-2023-0464}} and {{CVE-2023-23524}}.

{{dos}} describes this vulnerability. {{policy-graph}} describes the primary
mitigation for this vulnerability, a replacement for the policy tree structure.
{{updates}} provides updates to {{!RFC5280}} which implement this change.
Finally, {{other-mitigations}} discusses alternative mitigation strategies for
X.509 applications.

## Summary of Changes from RFC 5280

The algorithm for processing certificate policies and policy mappings is
replaced with one which builds an equivalent, but much more efficient structure.
This new algorithm does not change the validity status of any certification
path, nor which certificate policies are valid for it.

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{!RFC2119}} {{!RFC8174}}
when, and only when, they appear in all capitals, as shown here.

# Denial of Service Vulnerability {#dos}

This section discusses how the path validation algorithm defined in
{{Section 6.1.2 of !RFC5280}} can lead to a denial-of-service vulnerability in
X.509-based applications.

## Policy Trees

{{Section 6.1.2 of !RFC5280}} constructs the `valid_policy_tree`, a tree of
certificate policies, during certification path validation.
The nodes at any given depth in the tree correspond to
policies asserted by a certificate in the certification path. A node's
parent policy is the policy in the issuer certificate which was mapped to this
policy, and a node's children are the policies it was mapped to in the subject
certificate.

For example, suppose a certification path contains:

* An intermediate certificate which asserts policy OIDs OID1, OID2, and OID5.
  It contains mappings OID1 to OID3, and OID1 to OID4.

* An end-entity certificate which asserts policy OIDs OID2, OID3, and OID6.

This would result in the tree shown in {{basic-tree}}. Note that OID5 and OID6
are not included or mapped across the whole path, so they do not appear in the
final structure.

~~~ aasvg
                            +-----------+
           Root:            | anyPolicy |
                            +-----------+
                            |{anyPolicy}|
                            +-----------+
                             /          \
                            /            \
                           v              v
                  +------------+      +------------+
   Intermediate:  |    OID1    |      |    OID2    |
(OID5 discarded)  +------------+      +------------+
                  |{OID3, OID4}|      |   {OID2}   |
                  +------------+      +------------+
                        |                   |
                        |                   |
                        v                   v
                  +------------+      +------------+
     End-entity:  |    OID3    |      |    OID2    |
(OID6 discarded)  +------------+      +------------+
~~~
{: #basic-tree title="An Example X.509 Policy Tree"}

The complete algorithm for building this structure is described in steps (d),
(e), and (f) of {{Section 6.1.3 of !RFC5280}}, steps (h), (i), (j) of {{Section
6.1.4 of !RFC5280}}, and steps (a), (b), and (g) of {{Section 6.1.5 of
!RFC5280}}.

## Exponential Growth {#exponential-growth}

The `valid_policy_tree` grows exponentially in the worst case. In
step (d.1) of {{Section 6.1.3 of !RFC5280}}, a single policy P can produce
multiple child nodes if multiple issuer policies map to P. This can cause the
tree size to increase in size multiplicatively at each level.

In particular, consider a certificate chain where every intermediate certificate
asserts policies OID1 and OID2, and then contains the full Cartesian product of
mappings:

* OID1 maps to OID1
* OID1 maps to OID2
* OID2 maps to OID1
* OID2 maps to OID2

At each depth, the tree would double in size.
For example, if there are two intermediate certificates and one end-entity certificate, the resulting tree would be as depicted in {{exponential-tree}}.

~~~ aasvg
                        +-----------------------+
                        |        anyPolicy      |
                        +-----------------------+
                        |       {anyPolicy}     |
                        +-----------------------+
                         /                     \
                        /                       \
                       v                         v
            +------------+                      +------------+
            |    OID1    |                      |    OID2    |
            +------------+                      +------------+
            |{OID1, OID2}|                      |{OID1, OID2}|
            +------------+                      +------------+
             /         \                          /         \
            /           \                        /           \
           v             v                      v             v
  +------------+    +------------+    +------------+    +------------+
  |    OID1    |    |    OID2    |    |    OID1    |    |    OID2    |
  +------------+    +------------+    +------------+    +------------+
  |{OID1, OID2}|    |{OID1, OID2}|    |{OID1, OID2}|    |{OID1, OID2}|
  +------------+    +------------+    +------------+    +------------+
    |       |         |       |         |       |         |       |
    v       v         v       v         v       v         v       v
+------+ +------+ +------+ +------+ +------+ +------+ +------+ +------+
| OID1 | | OID2 | | OID1 | | OID2 | | OID1 | | OID2 | | OID1 | | OID2 |
+------+ +------+ +------+ +------+ +------+ +------+ +------+ +------+
~~~
{: #exponential-tree title="An Example X.509 Policy Tree with Exponential Growth"}

## Attack Vector

An attacker can use the exponential growth to mount a denial-of-service attack against
an X.509-based application. The attacker sends certificate chain as in {{exponential-growth}} and
triggers the target application's certificate validation process. For example,
the target application may be a TLS {{?RFC8446}} server that performs client
certificate validation. The target
application will consume far more resources processing the input than the
attacker consumed to send it, preventing it from servicing other clients.

# Avoiding Exponential Growth {#avoiding-exponential-growth}

This document mitigates the denial-of-service vulnerability described in {{dos}}
by replacing the policy tree with a policy graph structure, described in this
section. The policy graph grows linearly instead of exponentially. This removes
the asymmetric cost in policy validation.

X.509 implementations SHOULD perform policy validation by building a policy
graph, following the procedure described in {{updates}}. This replacement
procedure computes the same policies as in {{!RFC5280}}, however one of the
outputs is in a different form. See {{outputs}} for details.
{{other-mitigations}} describes alternative mitigations for implementations that
depend on the original, exponential-sized output.

## Policy Graphs {#policy-graph}

The tree structure from {{!RFC5280}} is an unnecessarily inefficient
representation of a certification path's policy mappings. A single certificate
policy may correspond to multiple nodes, but each node is identical, with identical
children. This redundancy is the source of the exponential growth described in
{{exponential-growth}}.

A policy graph is a directed acyclic graph of policy nodes.
Where {{!RFC5280}} adds multiple duplicate nodes, a policy graph adds a single node with multiple parents.
See {{updates}} for the procedure for building this structure.
{{exponential-tree-as-graph}} shows the updated representation of the example in {{exponential-tree}}.

~~~ aasvg
              +-----------+
              | anyPolicy |
              +-----------+
              |{anyPolicy}|
              +-----------+
              /           \
             /             \
            v               v
     +------------+  +------------+
     |    OID1    |  |    OID2    |
     +------------+  +------------+
     |{OID1, OID2}|  |{OID1, OID2}|
     +------------+  +------------+
          |      \    /     |
          |       \  /      |
          |        \/       |
          |        /\       |
          |       /  \      |
          v      v    v     v
     +------------+  +------------+
     |    OID1    |  |    OID2    |
     +------------+  +------------+
     |{OID1, OID2}|  |{OID1, OID2}|
     +------------+  +------------+
          |      \    /     |
          |       \  /      |
          |        \/       |
          |        /\       |
          |       /  \      |
          v      v    v     v
     +------------+  +------------+
     |    OID1    |  |    OID2    |
     +------------+  +------------+
~~~
{: #exponential-tree-as-graph title="A More Efficient Representation of an X.509 Policy Tree"}

This graph's size is bounded linearly by the total number of certificate
policies ({{Section 4.2.1.4 of RFC5280}}) and policy mappings ({{Section 4.2.1.5
of RFC5280}}). The policy tree from {{RFC5280}} is the tree of all paths from the root to a leaf in the policy graph,
so no information is lost in the graph representation.

## Verification Outputs {#outputs}

{{Section 6.1.6 of RFC5280}} describes the entire `valid_policy_tree` structure as
an output of the verification process. Section 12.2 of {{X.509}} instead only
outputs the authorities-constrained policies, the user-constrained policies,
and their associated qualifiers.

As the `valid_policy_tree` is the exponential structure, computing it
reintroduces the denial-of-service vulnerability. X.509 implementations
SHOULD NOT output the entire `valid_policy_tree` structure and instead SHOULD
limit output to just the set of authorities-constrained and/or user-constrained
policies, as described in {{X.509}}. {{update-outputs}} and
{{other-mitigations}} discuss other mitigations for applications where this
option is not available.

X.509 implementations MAY omit policy qualifiers from the output to simplify
processing. Note {{Section 4.2.1.4 of RFC5280}} already recommends that
certification authorities omit policy qualifiers from policy information terms.

# Updates to RFC 5280 {#updates}

This section provides updates to {{RFC5280}}. This implements the changes
described in {{avoiding-exponential-growth}}.

## Updates to Section 6.1

This update replaces a paragraph of {{Section 6.1 of RFC5280}} as follows:

OLD:

>   A particular certification path may not, however, be appropriate for
>   all applications.  Therefore, an application MAY augment this
>   algorithm to further limit the set of valid paths.  The path
>   validation process also determines the set of certificate policies
>   that are valid for this path, based on the certificate policies
>   extension, policy mappings extension, policy constraints extension,
>   and inhibit anyPolicy extension.  To achieve this, the path
>   validation algorithm constructs a valid policy tree.  If the set of
>   certificate policies that are valid for this path is not empty, then
>   the result will be a valid policy tree of depth n, otherwise the
>   result will be a null valid policy tree.

NEW:

>   A particular certification path may not, however, be appropriate for
>   all applications.  Therefore, an application MAY augment this
>   algorithm to further limit the set of valid paths.  The path
>   validation process also determines the set of certificate policies
>   that are valid for this path, based on the certificate policies
>   extension, policy mappings extension, policy constraints extension,
>   and inhibit anyPolicy extension.  To achieve this, the path
>   validation algorithm constructs a valid policy set, which may be empty if
>   no certificate policies are valid for this path.

## Updates to Section 6.1.2

This update replaces entry (a) of {{Section 6.1.2 of RFC5280}} with the following text:

{: type="(%c)"}
1. `valid_policy_graph`:  A directed acyclic graph of certificate
   policies with their optional qualifiers; each of the leaves
   of the graph represents a valid policy at this stage in the
   certification path validation.  If valid policies exist at
   this stage in the certification path validation, the depth of
   the graph is equal to the number of certificates in the chain
   that have been processed.  If valid policies do not exist at
   this stage in the certification path validation, the graph is
   set to NULL.  Once the graph is set to NULL, policy processing
   ceases.  Implementations MAY omit qualifiers if not returned
   in the output.

   Each node in the `valid_policy_graph` includes three data objects:
   the valid policy, a set of associated policy qualifiers, and a set of
   one or more expected policy values.

   Nodes in the graph can be divided into depths, numbered starting from zero.
   A node at depth x can have zero or more children at depth x+1 and, with the
   exception of depth zero, one or more parents at depth x-1. No other edges
   between nodes may exist.

   If the node is at depth x, the components of the node have
   the following semantics:

   {: type="(%d)"}
   1. The `valid_policy` is a single policy OID representing a valid policy for the path of length x.

   2. The `qualifier_set` is a set of policy qualifiers associated with the valid policy in certificate x.
      It is only necessary to maintain this field if policy qualifiers are returned to the application.
      See Section 6.1.5, step (g).

   3. The `expected_policy_set` contains one or more policy OIDs that would satisfy this policy in the certificate x+1.

   The initial value of the `valid_policy_graph` is a single node with
   `valid_policy` anyPolicy, an empty `qualifier_set`, and an
   `expected_policy_set` with the single value anyPolicy.  This node is
   considered to be at depth zero.

   The graph additionally satisfies the following invariants:

   * For any depth x and policy OID P-OID, there is at most one node at depth x whose `valid_policy` is P-OID.

   * The `expected_policy_set` of a node whose `valid_policy` is anyPolicy is always {anyPolicy}.

   * A node at depth x whose `valid_policy` is anyPolicy, except for the one at
     depth zero, always has exactly one parent: a node at depth x-1 whose
     `valid_policy` is also anyPolicy.

   * Each node at depth greater than 0 has either one or more parent nodes whose `valid_policy` is not anyPolicy,
     or a single parent node whose `valid_policy` is anyPolicy.
     That is, a node cannot simultaneously be a child of both anyPolicy and some non-anyPolicy OID.

   {{graph-initial}} is a graphic representation of the initial state of the
   `valid_policy_graph`.  Additional figures will use this format to
   describe changes in the `valid_policy_graph` during path processing.

   ~~~ aasvg
       +----------------+
       |   anyPolicy    |   <---- valid_policy
       +----------------+
       |       {}       |   <---- qualifier_set
       +----------------+
       |  {anyPolicy}   |   <---- expected_policy_set
       +----------------+
   ~~~
   {: #graph-initial title="Initial value of the valid_policy_graph State Variable"}

## Updates to Section 6.1.3

This update replaces steps (d), (e), and (f) of {{Section 6.1.3 of RFC5280}} with the following text:

{: type="(%c)" start="4"}
1. If the certificate policies extension is present in the
   certificate and the `valid_policy_graph` is not NULL, process
   the policy information by performing the following steps in
   order:

   {: type="(%d)"}
   1. For each policy P not equal to anyPolicy in the certificate policies extension,
      let P-OID denote the OID for policy P and P-Q denote the qualifier set for policy P.
      Perform the following steps in order:

      {: type="(%i)"}
      1. Let `parent_nodes` be the nodes at depth i-1 in the `valid_policy_graph` where P-OID is in the `expected_policy_set`.
         If `parent_nodes` is not empty, create a child node as follows:
         set the `valid_policy` to P-OID, set the `qualifier_set` to P-Q, set the `expected_policy_set` to {P-OID}, and set the parent nodes to `parent_nodes`.

         For example, consider a `valid_policy_graph` with a node of depth i-1 where the `expected_policy_set` is {Gold, White},
         and a second node where the `expected_policy_set` is {Gold, Yellow}.
         Assume the certificate policies Gold and Silver appear in the certificate policies extension of certificate i.
         The Gold policy is matched, but the Silver policy is not.
         This rule will generate a child node of depth i for the Gold policy.
         The result is shown as {{exact-match}}.

         ~~~ aasvg
             +-----------------+      +-----------------+
             |       Red       |      |       Blue      |
             +-----------------+      +-----------------+
             |       {}        |      |       {}        |   depth i-1
             +-----------------+      +-----------------+
             |  {Gold, White}  |      |  {Gold, Yellow} |
             +-----------------+      +-----------------+
                         \                   /
                          \                 /
                           \               /
                            v             v
                          +-----------------+
                          |      Gold       |
                          +-----------------+
                          |       {}        |   depth i
                          +-----------------+
                          |     {Gold}      |
                          +-----------------+
         ~~~
         {: #exact-match title="Processing an Exact Match"}

      2. If there was no match in step (i) and the `valid_policy_graph` includes a node of depth i-1 with the `valid_policy` anyPolicy,
         generate a child node with the following values:
         set the `valid_policy` to P-OID, set the `qualifier_set` to P-Q, set the `expected_policy_set` to {P-OID},
         and set the parent node to the anyPolicy node at depth i-1.

         For example, consider a `valid_policy_graph` with a node
         of depth i-1 where the `valid_policy` is anyPolicy.
         Assume the certificate policies Gold and Silver appear
         in the certificate policies extension of certificate
         i.  The Gold policy does not have a qualifier, but the
         Silver policy has the qualifier Q-Silver.  If Gold and
         Silver were not matched in (i) above, this rule will
         generate two child nodes of depth i, one for each
         policy.  The result is shown as {{unmatched-anypolicy}}.

         ~~~ aasvg
                           +-----------------+
                           |    anyPolicy    |
                           +-----------------+
                           |       {}        |
                           +-----------------+   depth i-1
                           |   {anyPolicy}   |
                           +-----------------+
                              /           \
                             /             \
                            /               \
                           v                 v
             +-----------------+          +-----------------+
             |      Gold       |          |     Silver      |
             +-----------------+          +-----------------+
             |       {}        |          |   {Q-Silver}    |   depth i
             +-----------------+          +-----------------+
             |     {Gold}      |          |    {Silver}     |
             +-----------------+          +-----------------+
         ~~~
         {: #unmatched-anypolicy title="Processing Unmatched Policies when a Leaf Node Specifies anyPolicy"}

   2. If the certificate policies extension includes the policy anyPolicy with the qualifier set AP-Q and either (a)
      `inhibit_anyPolicy` is greater than 0 or (b) i<n and the certificate is self-issued, then:

      For each policy OID P-OID (including anyPolicy) which appears in the `expected_policy_set` of some node in the `valid_policy_graph` for depth i-1,
      if P-OID does not appear as the `valid_policy` of some node at depth i, create a single child node with the following values:
      set the `valid_policy` to P-OID, set the `qualifier_set` to AP-Q, set the `expected_policy_set` to {P-OID},
      and set the parents to the nodes at depth i-1 where P-OID appears in `expected_policy_set`.

      This is equivalent to running step (1) above, as if the certificate policies extension contained a policy with OID P-OID and qualifier set AP-Q.

      For example, consider a `valid_policy_graph` with a node of depth i-1 where the `expected_policy_set` is {Gold, Silver},
      and a second node of depth i-1 where the `expected_policy_set` is {Gold}.
      Assume anyPolicy appears in the certificate policies extension of certificate i with policy qualifiers AP-Q, but Gold and Silver do not appear.
      This rule will generate two child nodes of depth i, one for each policy.
      The result is shown below as {{anypolicy-in-extension}}.

      ~~~ aasvg
          +-----------------+   +-----------------+
          |       Red       |   |       Blue      |
          +-----------------+   +-----------------+
          |       {}        |   |       {}        |   depth i-1
          +-----------------+   +-----------------+
          |  {Gold, Silver} |   |      {Gold}     |
          +-----------------+   +-----------------+
                  |         \            |
                  |          \           |
                  |           \          |
                  |            \         |
                  |             \        |
                  v              v       v
          +-----------------+   +-----------------+
          |     Silver      |   |       Gold      |
          +-----------------+   +-----------------+
          |     {AP-Q}      |   |      {AP-Q}     |   depth i
          +-----------------+   +-----------------+
          |    {Silver}     |   |      {Gold}     |
          +-----------------+   +-----------------+
      ~~~
      {: #anypolicy-in-extension title="Processing Unmatched Policies When the Certificate Policies Extension Specifies anyPolicy"}


   3. If there is a node in the `valid_policy_graph` of depth i-1 or less without any child nodes, delete that node.
      Repeat this step until there are no nodes of depth i-1 or less without children.

      For example, consider the valid_policy_graph shown in {{pruning}} below.
      The two nodes at depth i-1 that are marked with an 'X' have no children, and they are deleted.
      Applying this rule to the resulting graph will cause the nodes at depth i-2 that is marked with a 'Y' to be deleted.
      In the resulting graph, there are no nodes of depth i-1 or less without children, and this step is complete.

      ~~~ aasvg
                        +-----------+
                        |           | depth i-3
                        +-----------+
                        /     |     \
                       /      |      \
                      v       v       v
          +-----------+ +-----------+ +-----------+
          |           | |           | |     Y     | depth i-2
          +-----------+ +-----------+ +-----------+
                |     \       |             |
                |      \      |             |
                v       v     v             v
          +-----------+ +-----------+ +-----------+
          |     X     | |           | |     X     | depth i-1
          +-----------+ +-----------+ +-----------+
                        /     |     \
                       /      |      \
                      v       v       v
          +-----------+ +-----------+ +-----------+
          |           | |           | |           | depth i
          +-----------+ +-----------+ +-----------+
      ~~~
      {: #pruning title="Pruning the valid_policy_graph"}



2. If the certificate policies extension is not present, set the `valid_policy_graph` to NULL.

3. Verify that either `explicit_policy` is greater than 0 or the `valid_policy_graph` is not equal to NULL;

## Updates to Section 6.1.4

This update replaces step (b) of {{Section 6.1.4 of RFC5280}} with the following text:

{: type="(%c)" start="2"}
1. If a policy mappings extension is present, then for each issuerDomainPolicy ID-P in the policy mappings extension:

   {: type="(%d)"}
   1. If the policy_mapping variable is greater than 0 and there is a
      node in the `valid_policy_graph` of depth i where ID-P is the
      valid_policy, set `expected_policy_set` to the set of
      subjectDomainPolicy values that are specified as
      equivalent to ID-P by the policy mappings extension.

   2. If the policy_mapping variable is greater than 0,
      no node of depth i in the `valid_policy_graph` has a
      `valid_policy` of ID-P, but there is a node of depth i with a
      `valid_policy` of anyPolicy, then generate a child node of
      the node of depth i-1 that has a `valid_policy` of anyPolicy
      as follows:

      {: type="(%i)"}
      1. set the `valid_policy` to ID-P;

      2. set the `qualifier_set` to the qualifier set of the
         policy anyPolicy in the certificate policies
         extension of certificate i; and

      3. set the `expected_policy_set` to the set of
         subjectDomainPolicy values that are specified as
         equivalent to ID-P by the policy mappings extension.

   3. If the `policy_mapping` variable is equal to 0:

      {: type="(%i)"}
      1. delete the node, if any, of depth i in the `valid_policy_graph` where ID-P is the `valid_policy`.

      2. If there is a node in the `valid_policy_graph` of depth
         i-1 or less without any child nodes, delete that
         node.  Repeat this step until there are no nodes of
         depth i-1 or less without children.

## Updates to Section 6.1.5

This update replaces step (g) of {{Section 6.1.5 of RFC5280}} with the following text:

{: type="(%c)" start="7"}
1. Calculate the `user_constrained_policy_set` as follows.
   The `user_constrained_policy_set` is a set of policy OIDs, along with associated policy qualifiers.

   {:type="(%d)"}
   1. If the `valid_policy_graph` is NULL, set `valid_policy_node_set` to the empty set.

   2. If the `valid_policy_graph` is not NULL, set `valid_policy_node_set` to the set of policy nodes
      whose `valid_policy` is not anyPolicy and
      whose parent list is a single node with `valid_policy` of anyPolicy.

   3. If the `valid_policy_graph` is not NULL and contains a node of depth n with the `valid_policy` anyPolicy, add it to `valid_policy_node_set`.

   4. Compute `authority_constrained_policy_set`, a set of policy OIDs and associated qualifiers as follows. For each node in `valid_policy_node_set`:

      {:type="(%i)"}
      1. Add the node's `valid_policy` to `authority_constrained_policy_set`.

      2. Collect all qualifiers in the node, its ancestors, and descendants and associate them with `valid_policy`. Applications that do not use policy qualifiers MAY skip this step to simplify processing.

   4. Set `user_constrained_policy_set` to `authority_constrained_policy_set`.

   5. If the user-initial-policy-set is not anyPolicy:

      {:type="(%i)"}
      1. Remove any elements of `user_constrained_policy_set` which do not appear in user-initial-policy-set.

      2. If anyPolicy appears in `authority_constrained_policy_set` with qualifiers AP-Q, for each OID P-OID in user-initial-policy-set which does not appear in `user_constrained_policy_set`, add P-OID with qualifiers AP-Q to `user_constrained_policy_set`.

Additionally, this update replaces the final paragraph as follows:

OLD:

> If either (1) the value of `explicit_policy` variable is greater than
> zero or (2) the `valid_policy_tree` is not NULL, then path processing
> has succeeded.

NEW:

> If either (1) the value of `explicit_policy` is greater than
> zero or (2) the `user_constrained_policy_set` is not empty, then path processing
> has succeeded.

## Updates to Section 6.1.6 {#update-outputs}

This update replaces {{Section 6.1.6 of RFC5280}} with the following text:

> If path processing succeeds, the procedure terminates, returning a
> success indication together with final value of the `user_constrained_policy_set`,
> the `working_public_key`, the `working_public_key_algorithm`, and the
> `working_public_key_parameters`.
>
> Note the original procedure described in {{RFC5280}} included a
> `valid_policy_tree` structure as part of the output. This structure grows
> exponentially in the size of the input, so computing it risks
> denial-of-service vulnerabilities in X.509-based applications, such as
> {{CVE-2023-0464}} and {{CVE-2023-23524}}. Accordingly, this output is
> deprecated. Computing this structure is NOT RECOMMENDED.
>
> An implementation which requires `valid_policy_tree` for compatibility with
> legacy systems may compute it from `valid_policy_graph` by recursively
> duplicating every multi-parent node. This may be done on-demand when the
> calling application first requests this output. However, this computation may
> consume exponential time and memory, so such implementations SHOULD mitigate
> denial-of-service in other ways, such as limiting the depth or size of the
> tree.

# Other Mitigations {#other-mitigations}

X.509 implementations that are unable switch to the policy graph structure
SHOULD mitigate the denial-of-service attack in other ways. This section
describes alternate mitigation and partial mitigation strategies.

## Limit Certificate Depth

The policy tree grows exponentially in the depth of a certification path, so
limiting the depth and certificate size can mitigate the attack.

However, this option may not be viable for all applications. Too low of a limit
may reject existing paths which the application wishes to accept. Too high of a
limit may still admit a DoS attack for the application. By modifying the example
in {{exponential-growth}} to increase the number of policies asserted in each
certificate, an attacker could still achieve O(N^(depth/2)) scaling.

## Limit Policy Tree Size

The attack can be mitigated by limiting the number of nodes in the policy tree,
and rejecting the certification path if this limit is reached. This limit should
be set high enough to still admit existing valid certification paths for the
application, but low enough to no longer admit a DoS attack.

## Inhibit Policy Mapping

If policy mapping is disabled via the initial-policy-mapping-inhibit setting
(see {{Section 6.1.1 of RFC5280}}), the attack is mitigated. This also
significantly simplifies the X.509 implementation, which reduces the risk of
other security bugs. However, this will break compatibility with any existing
certification paths which rely on policy mapping.

To facilitate this mitigation, certificate authorities SHOULD NOT issue
certificates with the policy mappings extension ({{Section 4.2.1.5 of
RFC5280}}). Applications maintaining policies for accepted trust anchors are
RECOMMENDED to forbid this extension in participating certificate authorities.

## Disable Policy Checking

An X.509 validator can mitigate this attack by disabling policy validation
entirely. This may be viable for applications which do not require policy
validation. In this case, critical policy-related extensions, notably the policy
constraints ({{Section 4.2.1.11 of RFC5280}}), MUST be treated as unrecognized
extensions as in {{Section 4.2 of RFC5280}} and be rejected.

## Verify Signatures First

X.509 validators SHOULD verify signatures in certification paths before or in
conjunction with policy verification. This limits the attack to entities in
control of CA certificates. For some applications, this may be sufficient to
mitigate the attack. However, other applications may still be impacted. For
example:

* Any application that evaluates an untrusted PKI, such as a hosting provider
  that evaluates a customer-supplied PKI

* Any application that evaluates an otherwise trusted PKI, but where untrusted
  entities have technically-constrained intermediate certificates where policy
  mapping and path length are unconstrained.

# Implementation Status
{:removeinrfc="true"}

This section records the status of known implementations of the
protocol defined by this specification at the time of posting of
this Internet-Draft, and is based on a proposal described in
RFC 7942.  The description of implementations in this section is
intended to assist the IETF in its decision processes in
progressing drafts to RFCs.  Please note that the listing of any
individual implementation here does not imply endorsement by the
IETF.  Furthermore, no effort has been spent to verify the
information presented here that was supplied by IETF contributors.
This is not intended as, and must not be construed to be, a
catalog of available implementations or their features.  Readers
are advised to note that other implementations may exist.

According to RFC 7942, "this will allow reviewers and working
groups to assign due consideration to documents that have the
benefit of running code, which may serve as evidence of valuable
experimentation and feedback that have made the implemented
protocols more mature.  It is up to the individual working groups
to use this information as they see fit".

The following projects adopted the concept outlined in this document:

* {{BoringSSL}}

* {{LibreSSL}}

# Security Considerations

{{dos}} discusses how {{!RFC5280}}'s policy tree algorithm can lead to
denial-of-service vulnerabilities in X.509-based applications, such as
{{CVE-2023-0464}} and {{CVE-2023-23524}}.

{{updates}} replaces this algorithm to avoid this issue. As discussed in
{{policy-graph}}, the new structure scales linearly with the input. This means
input limits in X.509 validators will more naturally bound processing time,
thus avoiding these vulnerabilities.

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgements
{:numbered="false"}

The author thanks Bob Beck, Adam Langley, Matt Mueller, and Ryan Sleevi for
many valuable discussions that led to discovering this issue, understanding it,
and developing the mitigation. The author also thanks Martin Thomson and Job
Snijders for feedback on this document.
