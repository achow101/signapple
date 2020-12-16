# Code Signature Structure

In this document, the structure of an Apple Mach-O code signature.
Most of the information from here was determined by examining the available [source code](https://opensource.apple.com/source/Security/) for Apple's `Security` library.
Note that all numbers are big endian.

## Mach-O Executable

The Mach-O executable format contains space for a code signature.
In the Macho-O headers, the load command `LC_CODE_SIGNATURE` specifies the location and size of the code signature.
The code signature itself is part of the `LINKEDIT` section and is typically found at the end of the executable.

## Code Signature

The code signature itself consists of data structures called `Blob`s.

### Base `Blob`

Source code location: `OSX/libsecurity_utilities/lib/blob.h`

The base structure is called the `Blob`.
A `Blob` is a type-length-value structure.
`Blob`s are a magic value, total `Blob` length (includes magic and length), and variable length data.
The data depends on the specific type of blob being used.

```
struct Blob {
    uint32_t magic; // Magic bytes specific to each Blob subclass
    uint32_t length; // Size of the entire Blob, including magic and length
    char* data;
}
```

### `BlobWrapper`

Source code location: `OSX/libsecurity_utilities/lib/blob.h`

The `BlobWrapper` is a `Blob` which encapsulates some other encoded binary data.
This `Blob` type is used to contain the CMS signature.
It may also be used to encapsulate other binary data.
The magic for `BlobWrapper` is `0xfade0b01`.

```
struct BlobWrapper {
    uint32_t magic = 0xfade0b01;
    uint32_t length;
    char* data; // The binary data encapsulated by this BlobWrapper
```

### `SuperBlob`

Source code location: `OSX/libsecurity_utilities/lib/superblob.h`

The `SuperBlob` is a subclass of `Blob`.
Like `Blob`, `SuperBlob` is a generic class that is subclassed for specific data.
`SuperBlob`s contain multiple blobs.
In addition to the common `Blob` magic and length fields, `SuperBlob`s specify the number of `Blob`s they contain, and an index of the `Blob`s contained.
This index is simply an array of tuples.
The first value of the tuple is the type of the `Blob`, and the second value is the location of the `Blob`.
The location is an offset from the beginning of the `SuperBlob` (including the magic and length).

```
struct IndexEntry{
    uint32_t type;
    uint32_t offset; // Offset of the blob from the beginning of this SuperBlob
}

struct SuperBlob {
    uint32_t magic;
    uint32_t length;
    uint32_t count_blobs;
    IndexEntry entries[];
    Blob blobs[];
}
```

### `EmbeddedSignatureBlob`

Source code location: `OSX/libsecurity_codesigning/lib/sigblob.h`

The `EmbeddedSignatureBlob` is the `SuperBlob` that is actually used in the code signature.
The code signature data is all contained with an `EmbeddedSignatureBlob`.
During code signing, an `EmbeddedSignatureBlob` containing all of the signature data is constructed and inserted into the Mach-O executable at the location for the code signature.
The `EmbeddedSignatureBlob` has a magic value of `0xfade0cc0`.

```
struct EmbeddedSignatureBlob {
    uint32_t magic = 0xfade0cc0;
    uint32_t length;
    uint32_t count; // Number of entries
    IndexEntry entries[]; // Has `count` entries
    Blob blobs[]; // Has `count` blobs
}
```

For `EmbeddedSignatureBlob`'s index entries, the following types are defined (from: `OSX/libsecurity_codesigning/lib/codedirectory.h`):
```
enum {
    // Primary slot numbers.
    // These values are potentially present in the CodeDirectory hash array
    // under their negative values. They are also used in APIs and SuperBlobs.
    // Note that zero must not be used for these (it's page 0 of the main code array),
    // and it is important to assign contiguous (very) small values for them.
    //
    cdInfoSlot = 1,						// Info.plist
    cdRequirementsSlot = 2,				// internal requirements
    cdResourceDirSlot = 3,				// resource directory
    cdTopDirectorySlot = 4,				// Application specific slot
    cdEntitlementSlot = 5,				// embedded entitlement configuration
    cdRepSpecificSlot = 6,				// for use by disk rep
    cdEntitlementDERSlot = 7,			// DER representation of entitlements

    //
    // Virtual slot numbers.
    // These values are NOT used in the CodeDirectory hash array. They are used as
    // internal API identifiers and as types in SuperBlobs.
    // Zero is okay to use here; and we assign that to the CodeDirectory itself so
    // it shows up first in (properly sorted) SuperBlob indices. The rest of the
    // numbers is set Far Away so the primary slot set can expand safely.
    // It's okay to have large gaps in these assignments.
    //
    cdCodeDirectorySlot = 0,			// CodeDirectory
    cdAlternateCodeDirectorySlots = 0x1000, // alternate CodeDirectory array
    cdAlternateCodeDirectoryLimit = 0x1005,	// 5+1 hashes should be enough for everyone...
    cdSignatureSlot = 0x10000,			// CMS signature
    cdIdentificationSlot,				// identification blob (detached signatures only)
    cdTicketSlot,						// ticket embedded in signature (DMG only)
}
```

### `CodeDirectory`

Source code location: `OSX/libsecurity_codesigning/lib/codedirectory.h`

`CodeDirectory` is a `Blob` the describes the binary being signed.
The bulk of `CodeDirectory` is in it's hashes array.
The hashes array is an array of hashes of chunks of the binary.
The binary is divided into `pageSize` pieces.
Each piece is then hashed and added to the hashes array in the order of the original data.
`CodeDirectory` also specifies the hash algorithm used, the size of the hashes, an identifier string, and a team identifier string.
Additionally the hashes array contains negative indexes for "special" hashes.
These "special" hashes are of other non-executable data such as the `Info.plist` file, internal requirements blob, entitlements blob, and the resources directory.
The indexes of these "special" hashes are the negation of the "Primary slot" types used in `EmbeddedSignatureData`, i.e. the hash at index -1 is for the Info.plist file, at 02, the internal requirements, etc.
The magic value for `CodeDirectory` is `0xfade0c02`.

Several of `CodeDirectory`'s fields only exist after certain version numbers.
Some of these fields are not supported by `signapple` because their exact usage is not yet determined.

The identifier and team id strings in `CodeDirectory` are null-terminated strings.

```
struct CodeDirectory {
    uint32_t magic = 0xfade0c02;
    uint32_t length;
    uint32_t version;
    uint32_t flags;
    uint32_t hashOffset; // Offset from the beginning of CodeDirectory of the element at index 0 of the hashes array
    uint32_t identOffset; // Offset from the beginning of CodeDirectory of the identifer string
    uint32_t nSpecialSlots; // Number of "special" (negative index) hash array elements
    uint32_t nCodeSlots; // Number of ordinary hash array elements
    uint32_t codeLimit; // The offset from the beginning of the Mach-O executable up to which the hashes cover
    uint8_t hashSize; // Size in bytes of each hash
    uint8_t hashType; // The type of hash
    uint8_t platform; // Platform identiferl zero if not platform binary
    uint8_t pageSize; // The log2 of the page size in bytes; 0 => infinite
    uint32_t spare; // Unused (must be zero)
    uint32_t scatterOffset; // Offset from the beginning of CodeDirectory of the "scatter vector" (zero if absent) (unsupported by signapple)
    uint32_t teamIDOffset; // Offset from the beginning of CodeDirectory of the team ID string
    uint32_t spare3; // Unused (must be zero)
    uint64_t codeLimit64; // codeLimit, but 64 bits (unsupported by signapple)
    uint64_t execSegBase; // Offset of the executable segment (unsupported by signapple)
    uint64_t execSegLimit; // Limit of the executable segment (unsupported by signapple)
    uint64_t execSegFlags; // Exec segment flags (unsupported by signapple)
    uint32_t runtime; // Runtime version (unsupported by signapple)
    uint32_t preEncryptOffset; // Offset of pre-encrypt hash slots (unsupported by signapple)

    // Note that the following variable length fields may be found in a different order
    char* identifer; // Null terminated identifier string
    char* teamID; // Null terminated team ID string
    char* hashArray[]; // Hashes array. Positive indexes are hashes of the executable, negative indexes are "special" hashes
}
```

#### Special hashes

There are seven current special hash slots.
The negative of the slot number is the index in the hashes array.
These hashes must be consecutive, thus if a special hash slot is unused, the hash is listed as all 0's.
The current slot numbers are:

1. `cdInfoSlot`: Hash of the `<app_name>.app/Contents/Info.plist` file.
2. `cdRequirementsSlot`: Hash of the Internal Requirements blob. See [below](#Internal-Requirements)
3. `cdResourceDirSlot`: Hash of the `<app_name>.app/Contents/_CodeSignature/CodeResources` file. This file is a plist file generated during code signing and it contains the hashes of resources not part of the executable. TODO: Figure out how to generate this file.
4. `cdTopDirectorySlot`: Apple source code says "Application specific slot". Actual use is unknown. Unsupported by `signapple`.
5. `cdEntitlementSlot`: Hash of the embedded entitlements configuration.
6. `cdRepSpecificSlot`: Apple source code says "for use by disk rep". Actual use is unknown. Unsupported by `signapple`.
7. `cdEntitlementDERSlot`: Hash of the DER representation of entitlements.

### Internal Requirements

Source code location: `OSX/libsecurity_codesigning/lib/requirement.h`

Internal requirements are stored in a `Requirements` `SuperBlob`.
`Requirements` contains one or more `Requirement` blobs.
These `Requirement` blobs will be described below.
The magic for `Requirements` is `0xfade0c01`.
`Requirements` defines the following index types:

```
enum SecRequirementType {
    kSecHostRequirementType =			1,	/* what hosts may run us */
    kSecGuestRequirementType =			2,	/* what guests we may run */
    kSecDesignatedRequirementType =		3,	/* designated requirement */
    kSecLibraryRequirementType =		4,	/* what libraries we may link against */
    kSecPluginRequirementType =			5,	/* what plug-ins we may load */
    kSecInvalidRequirementType,				/* invalid type of Requirement (must be last) */
}
```

```
struct IndexEntry {
    SecRequirementType type;
    uint32_t offset;
}

struct {
    uint32_t magic = 0xfade0c01;
    uint32_t length;
    SeqRequirementType index[];
    Requirement blobs[];
}
```

#### `Requirement`

Source code location: `OSX/libsecurity_codesigning/lib/requirement.h`

The `Requirement` is a `Blob` which contains a requirement expression for the scope which it's type in the `Requirements` index states.
`Requirement` blobs can currently only have requirement expressions.
These expressions are a type of opcode based scripting language and define constraints for running the binary.
`Requirement` has the magic `0xfade0c00`

```
struct Requirement {
    uint32_t magic = 0xfade0c00;
    uint32_t length;
    uint32_t mKind = 1; // There is only one kind, expression kind, and it has a value of 1
    Expression expr;
}
```

An `Expression` is a series of opcodes and their arguments.
Each opcode in an `Expression` is a `uint32_t`.
Variable length arguments in an `Expression` are prefixed by their length (`uint32_t`) and will be followed by 0's to ensure the next item is aligned to a 4 byte offset.
The padding is not part of the argument length.

`Expression` opcodes will have their high byte used as flags.
In addition to `Expression` opcodes, there are opcodes for `MatchOperation`s which are used as extra comparators for the arguments.
The opcodes are (from `OSX/libsecurity_codesigning/lib/requirement.h`):

```
// exprForm opcodes.
//
// Opcodes are broken into flags in the (HBO) high byte, and an opcode value
// in the remaining 24 bits. Note that opcodes will remain fairly small
// (almost certainly <60000), so we have the third byte to play around with
// in the future, if needed. For now, small opcodes effective reserve this byte
// as zero.
// The flag byte allows for limited understanding of unknown opcodes. It allows
// the interpreter to use the known opcode parts of the program while semi-creatively
// disregarding the parts it doesn't know about. An unrecognized opcode with zero
// flag byte causes evaluation to categorically fail, since the semantics of such
// an opcode cannot safely be predicted.
//
enum {
	// semantic bits or'ed into the opcode
	opFlagMask =	 0xFF000000,	// high bit flags
	opGenericFalse = 0x80000000,	// has size field; okay to default to false
	opGenericSkip =  0x40000000,	// has size field; skip and continue
};

enum ExprOp {
	opFalse,					// unconditionally false
	opTrue,						// unconditionally true
	opIdent,					// match canonical code [string]
	opAppleAnchor,					// signed by Apple as Apple's product
	opAnchorHash,					// match anchor [cert hash]
	opInfoKeyValue,					// *legacy* - use opInfoKeyField [key; value]
	opAnd,						// binary prefix expr AND expr [expr; expr]
	opOr,						// binary prefix expr OR expr [expr; expr]
	opCDHash,					// match hash of CodeDirectory directly [cd hash]
	opNot,						// logical inverse [expr]
	opInfoKeyField,					// Info.plist key field [string; match suffix]
	opCertField,					// Certificate field, existence only [cert index; field name; match suffix]
	opTrustedCert,					// require trust settings to approve one particular cert [cert index]
	opTrustedCerts,					// require trust settings to approve the cert chain
	opCertGeneric,					// Certificate component by OID [cert index; oid; match suffix]
	opAppleGenericAnchor,			        // signed by Apple in any capacity
	opEntitlementField,				// entitlement dictionary field [string; match suffix]
	opCertPolicy,					// Certificate policy by OID [cert index; oid; match suffix]
	opNamedAnchor,					// named anchor type
	opNamedCode,					// named subroutine
	opPlatform,					// platform constraint [integer]
	opNotarized,					// has a developer id+ ticket
	opCertFieldDate,				// extension value as timestamp [cert index; field name; match suffix]
	opLegacyDevID,					// meets legacy (pre-notarization required) policy
	exprOpCount					// (total opcode count in use)
};

// match suffix opcodes
enum MatchOperation {
	matchExists,					// anything but explicit "false" - no value stored
	matchEqual,					// equal (CFEqual)
	matchContains,					// partial match (substring)
	matchBeginsWith,				// partial match (initial substring)
	matchEndsWith,					// partial match (terminal substring)
	matchLessThan,					// less than (string with numeric comparison)
	matchGreaterThan,				// greater than (string with numeric comparison)
	matchLessEqual,					// less or equal (string with numeric comparison)
	matchGreaterEqual,				// greater or equal (string with numeric comparison)
	matchOn,					// on (timestamp comparison)
	matchBefore,					// before (timestamp comparison)
	matchAfter,					// after (timestamp comparison)
	matchOnOrBefore,				// on or before (timestamp comparison)
	matchOnOrAfter,					// on or after (timestamp comparison)
	matchAbsent,					// not present (kCFNull)
};
```

### `EntitlementBlob`

Source code location: `OSX/libsecurity_codesigning/lib/sigblob.h`

The entitlements for this executable encoded as a plist file embedded in a `Blob`.
These entitlements are a dictionary mapping strings to a variety of possible values.
This is essentially a `BlobWrapper` for a plist file.
The magic for `EntitlementBlob` is `0xfade7171`.

```
struct EntitlementBlob {
    uint32_t magic = 0xfade7171;
    uint32_t length;
    char* data; // Entitlement as a plist file
}
```

### `EntitlementDERBlob`

Source code location: `OSX/libsecurity_codesigning/lib/sigblob.h`

Like `EntitlementBlob` but instead of plist data, the entitlements are encoded using DER.
The magic for `EntitlementDERBlob` is `0xfade7172`

```
struct EntitlementDERBlob {
    uint32_t magic = 0xfade7172;
    uint32_t length;
    char* data; // Entitlement DER encoded data
}
```

TODO: Find ASN.1 for entitlement encoding

### Signature

The signature itself is a DER encoded message and signature using [RFC 5652 Cryptographic Message Syntax (CMS)](https://tools.ietf.org/html/rfc5652).
The entire CMS binary data is contained within a `BlobWrapper`.
The CMS data contains the certificate (and its chain) that was used to sign this binary.
It also includes the message that was signed.
For code signatures, the message signed contains a "message_digest" field which contains the hash of the `CodeDirectory`.
Additionally two Apple specific fields, HashAgilityV1 and HashAgilityV2, contain the same `CodeDirectory` hash.
The effect is that the signature covers the hash of this message which contains the hash of the `CodeDirectory` which contains the hashes of the binary itself as well as other auxiliary data.
Thus the code signature covers everything that is distributed to the end user.

The signature also appears to contain a timestamp, so there is likely to be some phoning home involved. This has not yet been investigated.

TODO: Figure out the exact encoding of the final signed message

## Final Layout

In the end, the signed binary that is produced has the following layout:

```
Mach-O Executable
    Mach-O headers
        ...
        <other headers>
        ...
        LC_CODE_SIGNATURE description
    ...
    <normal binary stuff>
    ...
    LC_CODE_SIGNATURE section
        EmbeddedSignatureBlob
            CodeDirectory
                ...
            Requirements
                Requirement
                    Expression
                ...
            Entitlement
                Entitlement Plist
            BlobWrapper
                CMS Signature
                    Certificate chain
                    Message
                    Signature
```
