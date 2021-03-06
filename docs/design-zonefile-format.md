# Zone File Format

A zone file is a text file containing a textual representation of RAINS entries.
Typically, a zone file describes all entries of a zone. But it can also be used
to pre-load entries at startup of a caching server or a cache to output the
currently stored entries. It is RAINS analog to DNS's zone file format defined
in section 5 of [2], used by BIND [3] and many more.

## Format

A zone file contains a section or a sequence of section. A section typically
starts on a new line. Each section consists of several elements. At least one
white space (space, tab, return) acts as a delimiter between elements. A comment
starts with a ";" (semicolon) which results in the rest of the line being
ignored by the parser. Empty lines are allowed anywhere in the file, with or
without comments.

Parentheses "()", brackets "[]" and types (type name between semicolons e.g.
:ip4:) are static terms. Each term starting with a lowercase character stands
for an arbitrary string value. The meaning of this value is specified in the
RAINS data model. Similar to regex we use the following special characters which
are not part of the syntax.

- "{}" to group terms (as parenthesis are part of the syntax)
- "|" either term on the left or term on the right (not both)
- "\*" arbitrary number of occurrences of the previous term (including none)
- "\+" at least one occurrence of the previous term

### Special Encodings

- ";" represents the beginning of a comment. The remainder of the line is
  ignored.
- "<" represents the nil value of a shard's rangeFrom
- ">" represents the nil value of a shard's rangeTo


## BNF of the zonefile format

<sections> ::= "" | <sections> <assertion> | <sections> <shard> | <sections> <pshard> | <sections> <zone>
<zone> ::= <zoneBody> | <zoneBody> <annotation>
<zoneBody> ::= ":Z:" <subjectZone> <context> "[" <zoneContent> "]"
<zoneContent> ::= "" | <zoneContent> <assertion> | <zoneContent> <shard>
<shard> ::= <shardBody> | <shardBody> <annotation>
<shardBody> ::= ":S:" <shardRange> "[" <shardContent> "]" | ":S:" <subjectZone> <context> <shardRange> "[" <shardContent> "]"
<shardRange> ::= <rangeBegin> <rangeEnd> | <rangeBegin> ">" | "<" <rangeEnd> | "<" ">"
<shardContent> ::= "" | <shardContent> <assertion>
<pshard> ::= <pshardBody> | <pshardBody> <annotation>
<pshardBody> ::= ":P:" <shardRange> <pshardContent> | ":P:" <subjectZone> <context> <shardRange> <pshardContent>
<pshardContent> ::= <bloomFilter>
<bloomFilter> ::= :bloomFilter: "[" <hashTypes> "]" <nofHashFunctions> <bfOpMode> <bloomFilterData>
<hashTypes> ::= <hashType> | <hashTypes> <hashType>
<assertion> ::= <assertionBody> | <assertionBody> <annotation>
<assertionBody> ::= ":A:" <name> "[" <objects> "]" | ":A:" <name> <subjectZone> <context> "[" <objects> "]"
<objects> ::= <name> | <ip6> | <ip4> | <redir> | <deleg> | <nameset> | <cert> | <srv> | <regr> | <regt> | <infra> | <extra> | <next>
<name> ::= <namebody> | <name> <namebody>
<ip6> ::= <ip6body> | <ip6> <ip6body>
<ip4> ::= <ip4body> | <ip4> <ip4body>
<redir> ::= <redirbody> | <redir> <redirbody>
<deleg> ::= <delegbody> | <deleg> <delegbody>
<nameset> ::= <namesetbody> | <nameset> <namesetbody>
<cert> ::= <certbody> | <cert> <certbody>
<srv> ::= <srvbody> | <srv> <srvbody>
<regr> ::= <regrbody> | <regr> <regrbody>
<regt> ::= <regtbody> | <regt> <regtbody>
<infra> ::= <infrabody> | <infra> <infrabody>
<extra> ::= <extrabody> | <extra> <extrabody>
<next> ::= <nextbody> | <next> <nextbody>
<namebody> ::= ":name:" <cname> "[" <objectTypes> "]"
<ip6body> ::= ":ip6:" <ip6Addr>
<ip4body> ::= ":ip4:" <ip4Addr>
<redirbody> ::= ":redir:" <redirname>
<delegbody> ::= ":deleg:" ":ed25519:" <keyphase> <publicKeyData>
<namesetbody> ::= ":nameset:" <freeText>
<certbody> ::= ":cert:" <protocolType> <certificatUsage> <hashType> <certData>
<srvbody> ::= ":srv:" <serviceName> <port> <priority>
<regrbody> ::= ":regr:" <freeText>
<regtbody> ::= ":regt:" <freeText>
<infrabody> ::= ":infra:" ":ed25519:" <keyphase> <publicKeyData>
<extrabody> ::= ":extra:" ":ed25519:" <keyspace> <keyphase> <publicKeyData>
<nextbody> ::= ":next:" ":ed25519:" <keyphase> <publicKeyData> <validFrom> <validSince>
<objectTypes> ::= <objectType> | <objectTypes> <objectType>
<objectType> ::= ":name:" | ":ip6:" | ":ip4:" | ":redir:" | ":deleg:" |  
                 ":nameset:" | ":cert:" | ":srv:" | ":regr:" | ":regt:" |  
                 ":infra:" | ":extra:" | ":next:" |
<freeText> ::= <word> | <freeText> <word>
<protocolType> ::= ":unspecified:" | ":tls:"
<certificatUsage> ::= ":trustAnchor:" | ":endEntity:"
<hashType> ::= ":noHash:" | ":sha256:" | ":sha384:" | ":sha512:" | ":fnv64:" | ":murmur364:"
<bfOpMode> ::= ":standard:" | ":km1:" | ":km2:"
<annotation> ::= "(" <annotationBody> ")"
<annotationBody> ::= <signature> | <annotationBody> <signature>
<signature> ::= <sigMetaData> | <sigMetaData> <signatureData>
<sigMetaData> ::= ":sig:" ":ed25519:" ":rains:" <keyphase> <validFrom> <validSince>

TODO CFE define the types of some of the non terminals. Most of them are strings.

## Implementation

- readLineFunction: reads next line, separates line by comment delimiter,
  returns scanner to the content part or false if end of line
- parseFunction: takes a scanner as input which splits on white spaces. If the
  scanner is at the end, invoke readLineFunction() to override scanner and
  continue parsing. If no new entries and last entry parsed correctly, return
  content else error.

## Example

An zone file example for the domain example.com.

:Z: example com. [  
    :S: < > [  
        :A: bar  [ :ip4: 192.0.2.0 ]  
        :A: baz  [ :ip4: 192.0.2.1 ]  
        :A: foo [  
                :ip6:      2001:db8::  
                :ip4:      192.0.2.2  
        ]  
    ]  
    :S: bar foo [  
        :A: baz  [ :ip4: 192.0.2.1 ] (TODO CFE add sig meta data)  
    ] (TODO CFE add sig meta data)  
]
or equivalent
:S: example com. < > [  
    :A: bar  [ :ip4: 192.0.2.0 ]  
    :A: baz  [ :ip4: 192.0.2.1 ]  
    :A: foo [  
            :ip6:      2001:db8::  
            :ip4:      192.0.2.2  
    ]  
]  
:S: example com. bar foo [  
    :A: baz  [ :ip4: 192.0.2.1 ] (TODO CFE add sig meta data)  
] (TODO CFE add sig meta data)  

## Bibliography
[1] DNS zone file https://en.wikipedia.org/wiki/Zone_file
[2] DNS zone file format, Section 5 https://tools.ietf.org/html/rfc1035
[3] BIND https://www.isc.org/downloads/bind/