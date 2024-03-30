# *`gen-tpm2-cmd-interface`*
Generate TCG TPM2 interface code in Rust.

`gen-tpm2-cmd-interface` takes the Command/Response, Type and Algorithm tables as extracted from the TCG TPM2 Library by
`extract-tpm2-spec-tables` as input and produces corresponding interface code in Rust.

## Features
- The set of generated type definitions as well as related (un)marshalling code for each is completely under user
  control. Starting out from an initial set as specified by the user, like e.g. "unmarshal all command params" and
  "marshal all response params", `gen-tpm2-cmd-interface` would walk the dependency graph and output minimal, but
  complete and self-contained code.
- Natural mapping of TCG TPM2 Library type to Rust types. In particular, structure types resembling the "discriminated
  union" pattern are represented as Rust enums.
- No `unsafe` code by default. Possibility to opt-in to certain `unsafe` optimizations, as well as to panic-free
  code requiring certain `unsafe` constructs.
- `[no_std]` compatible.
- Embedded-friendly memory handling. All unmarshalled structure instances are allocated on the heap in order to avoid
  stack overruns. Memory allocations don't fail with a panic, but gracefully return with `TPM_RC_MEMORY`.
- Versatile and consistent feature configuration support throughout the generated code. Conditional features as found in
  the TCG TPM2 Library specification, like `ECC`, `RSA`, `CMAC` and so on, are getting mapped to corresponding Cargo
  features each. Likewise, algorithms from the Algorithm Registry (`TPM_ALG_ID`) and individual ECC curves are getting
  gated by a corresponding Cargo feature each. All such Cargo features are getting propagated through the closure
  dependency graph properly, meaning that all emitted dependencies would only get enabled as needed.
- Minimal set of unmarshal limits to be specified. The generated code will calculate derived values from a minimal set
  of limits to be passed to the unmarshalling API. For example, `PCR_SELECT_MAX` would get computed from the specified
  `IMPLEMENTATION_PCR`, if needed. Furthermore, certain limits like `MAX_DIGEST_SIZE` are getting computed in accordance
  to the set of hashes enabled in the Cargo feature configuration.
- Flexible input buffer management. Unmarshalled structures' byte array members all reference lean slices of the input
  buffer initially. Primitives for transforming the buffers into owned copies are provided and can be invoked selectively
  on an as-needed basis.

## Compilation
A plain
```
cargo build
```
from the top-level source directory will do. After successful compilation, you will find the resulting binaries
at `./target/debug/gen-tpm2-cmd-interface`.


## Usage
### Input table preparation
Four sets of input tables will be needed, three of which are supposed to be the result of extraction by means of the
`extract-tpm2-spec-tables` utility from the TCG TPM2 Library and the TCG Algorithm Registry respectively. The fourth
will get created manually and serves the purpose of defining possible RSA key sizes, i.e. `$RSA_KEY_SIZES_BITS`.

**_Warning: for the TCG Algorithm Registry, only revision 01.32 will work in conjunction with the current TCG TPM2
Library revision 01.59. The subsequently published revision 01.33 will not work._** The reason is that the more recent
TCG ALgorithm Registry revision includes some new algorithms for which the TCG TPM2 Library revision 01.59, Part2 lacks
some needed structure definitions, like e.g. a definition of `TPMS_SIGNATURE_LMSS` which would be needed by the
`TPMU_SIGNATURE` union.

In what follows, it is assumed that the three extracted sets live in files `tpm2_algorithms.csv`, `tpm2_structures.csv`
and `tpm2_commands.csv`. A fourth one named `tpm2_vendor.csv` with contents
```
BEGINTABLE "Vendor amendment to TCG Algorithm Registry" Definition of (UINT16) RSA_KEY_BITS Constants
Name;Value;Dep
RSA_KEY_BITS_1024;1024;rsa1024
RSA_KEY_BITS_2048;2048;rsa2048
RSA_KEY_BITS_3072;3072;rsa3072
RSA_KEY_BITS_4096;4096;rsa4096
RSA_KEY_BITS_8192;8192;rsa8192
RSA_KEY_BITS_16384;16384;rsa16384
ENDTABLE

BEGINTABLE "Vendor amendment to TCG Algorithm Registry" Defines for RSA key size Values
Name;Value
RSA_KEY_SIZES_BITS;{RSA_KEY_BITS_1024, RSA_KEY_BITS_2048, RSA_KEY_BITS_3072, RSA_KEY_BITS_4096, RSA_KEY_BITS_8192, RSA_KEY_BITS_16384}
ENDTABLE
```
must get created manually.

The following tweaks need to get applied to the extracted table sets each:
- Tables from TCG Algorithm Registry (rev 01.32):
  - Remove the `TPM_ALG_SHA` entry from the `TPM_ALG_ID` table as it conflicts with `TPM_ALG_SHA1`.
  - Remove the `E` flag from the `TPM_ALG_SM2` entry in the `TPM_ALG_ID` table. Otherwise `!ALG` macro expansion in
    e.g. the definition of `TPMI_ALG_ASYM_SCHEME` or `TPMU_ASYM_SCHEME` will cause conflicting entries. Moreover, a
    definition of `TPMS_ENC_SCHEME_SM2` would be needed, but is missing. Note that removing the `E` flag from
    `TPM_ALG_SM2` reverts the entry to what had originially been specified in the `TPM_ALG_ID` version found the TCG
    TPM2 Library (rev 01.59), Part 2: Structures.
- Tables from TCG TPM2 Library (rev 01.59), Part 2: Structures:
  - Remove the `TPM_ALG_ID` and `TPM_ECC_CURVE` tables as they conflict with the definitions of the
    TCG Algorithm Registry.
  - Add an empty "Dep" CSV column to each entry from the `TPM_CAP` table missing it.
  - Rename the "`sign / encrypt`" entry from the `TPMA_OBJECT` table to "`signEncrypt`".
- Tables from TCG TPM2 Library (rev 01.59), Part 3: Commands:
  - Fix a typo, replace the reference to "`TPM_CC_CreateLoade`" in the `TPM2_CreateLoaded` command definition table by
    "`TPM_CC_CreateLoaded`".

### Invocation
The overall invocation syntax is
```
gen-tpm2-cmd-interface [CODEGEN-OPTS] {-t <TABLES-CSV-FILE>}... <WHAT>
```
where `<TABLES-CSV-FILE>` referes to any of the previously mentioned `tpm2_algorithms.csv`, `tpm2_structures.csv` or
`tpm2_commands.csv` as extracted by `extract-tpm2-spec-tables` or to the manually created `tpm2_vendor.csv`. Obviously
the `-t` option can (and is supposed to) be given more than once.

The `<WHAT>` is specified as one or more flags identifying the desired generated code type alongside a pattern to be
matched on the type names each. For selecting command/response parameter or handle area structures, note that the
command params/handles representation structures get an `_COMMAND_PARAMS` or `_COMMAND_HANDLES` suffix appended each to
the command name internally and similar for responses, but with `_RESPONSE_PARAMS` and `_RESPONSE_HANDLES` respectively.
The flags identifying the desired code type generation are:
| Flag | Meaning                                                                                          |
|------|--------------------------------------------------------------------------------------------------|
| `-d` | Emit only a type definition.                                                                     |
| `-u` | Emit unmarshalling code, implies `-d`.                                                           |
| `-m` | Emit marshalling code, implies `-d`.                                                             |
| `-l` | Emit a `::try_clone()` implementation for making an instance an owner of its referenced buffers. |

Example:
```
gen-tpm2-cmd-interface      \
    -t tpm2_algorithms.csv  \
    -t tpm2_structures.csv  \
    -t tpm2_commands.csv    \
    -t tpm2_vendor.csv      \
	-u '.*_COMMAND_PARAMS   \
	-u '.*_COMMAND_HANDLES  \
	-m '.*_RESPONSE_PARAMS  \
	-m '.*_RESPONSE_HANDLES
```
would generate definitions and associated unmarshalling code for all command parameter and handle areas respectively and likewise
definitions and marshalling code for the response counterparts (plus all dependencies referenced therefrom, of course).

The TCG TPM2 Library specification, Part2: Structures introduces the notion of conditional types, which refers to type
definitions effectively expanding into two separate actual types, where the second one would allow a certain set of
additional enumeration values (usually `NULL` handles) somewhere in its contents. In case code generation for such a
type with the conditional enumeration values enabled is explicitly needed, use uppercase variants of the flags list
above for selecting those.

Example:
```
gen-tpm2-cmd-interface      \
    -t tpm2_algorithms.csv  \
    -t tpm2_structures.csv  \
    -t tpm2_commands.csv    \
    -t tpm2_vendor.csv      \
	-d 'TPMT_HA'            \
	-D 'TPMT_HA'
```
would emit two separate definition variants of the `TPMT_HA` tagged union: once without `TPM_ALG_NULL` and once with it
included. The two corresponding Rust types would be named `TpmtHa` and `TpmtHaWCV` respectively where "WCV" is short for
"with conditional values". The naming is stable, meaning that if you were to omit the non-conditional variant, i.e. the
lowercase `-d`, from the example above, the generated type with the conditional values enabled would still be named
`TpmtHaWCV`.

Finally, the `-c` flag enables the generation of a `with_tpm_commands` Rust macro, which allows you to have some custom
macro invoked repeatedly per each defined command with a special structure containing all possibly needed information
about the command passed to it. The intent is to facilitate generic, macro-driven code generation tailored to the
individual commands each.

#### Unsafe optimizations
There are a couple of experimental `unsafe` code optimizations implemented. All of these need explicit opt-in to be
enabled, see `gen-tpm2-cmd-interface -h` for the options.
