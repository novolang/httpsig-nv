# httpsig-nv

HTTP Message Signatures, specified in
[RFC 9421](https://www.rfc-editor.org/rfc/rfc9421), let a sender sign parts of
an HTTP request or response and let the receiver check that those parts were not
changed on the way. The signature does not cover the whole message. It covers
a chosen list of **components**, such as the method, the authority, the path,
and some header fields, so it survives the changes that proxies make to the
rest. This package brings HTTP Message Signatures to novo-lang. It builds the
signature base, signs it and verifies it, and reads and writes the
`Signature-Input`, `Signature` and `Accept-Signature` fields through
[sfv-nv](https://novo-lang.org/packages/sfv-nv).

## What it is

A signature is made in four steps.

1. The signer picks the **covered components** and the **signature
   parameters**: `created`, `expires`, `nonce`, `alg`, `keyid` and `tag`.
2. The signer builds the **signature base**, a text with one line for each
   covered component and a last line that repeats the list and the parameters.
3. The signer signs the bytes of that text with a key.
4. The signer adds two fields to the message. `Signature-Input` holds the list
   and the parameters, and `Signature` holds the signature bytes. Both are
   labelled, so a message can carry several signatures.

The verifier reads the two fields, builds the signature base again from the
message it received, and checks the signature against it.

A **component** is either an HTTP field, named in lower case (`content-type`),
or a **derived component** whose name starts with `@`: `@method`,
`@target-uri`, `@authority`, `@scheme`, `@request-target`, `@path`, `@query`,
`@query-param` and `@status`. A component may carry parameters.

| Parameter | Meaning |
| --- | --- |
| `sf` | Write the field strictly as the Structured Field it is. |
| `key` | Take one member of a Dictionary field. |
| `bs` | Wrap each field line as a Byte Sequence before joining them. |
| `tr` | Take the field from the trailers. |
| `req` | Take the component from the request that a response answers. |
| `name` | The query parameter that `@query-param` reads. |

## Install

```
novo pkg add httpsig-nv
```

## Example

This program signs a request with an HMAC key, then verifies it from the two
field values.

```novo
use std.bytes
use hsigalg
use hsigmsg
use hsigtypes
use httpsig
use sfvtypes

fn main() [io]
    let headers = [hsigtypes.field("Date", "Tue, 20 Apr 2021 02:07:55 GMT"), hsigtypes.field("Content-Type", "application/json")]
    match hsigmsg.request("POST", "https://example.com/foo?param=Value", headers)
        Err(e) => println(e.message())
        Ok(msg) =>
            let components = [hsigtypes.component("@method"), hsigtypes.component("@authority"), hsigtypes.component("@path"), hsigtypes.component("content-type")]
            let params = [sfvtypes.param("created", SfvInteger(1618884473)), sfvtypes.param("keyid", SfvString("test-shared-secret"))]
            let secret = bytes.from_str("a shared secret")
            match httpsig.sign(msg, None, "sig1", components, params, HsigHmacKey(secret))
                Err(e) => println(e.message())
                Ok(signed) =>
                    println("Signature-Input: " + signed.signature_input)
                    println("Signature: " + signed.signature)
                    match httpsig.verify(msg, None, [signed.signature_input], [signed.signature], "sig1", HsigHmacVerifyKey(secret))
                        Ok(v) => println("verified " + v.label)
                        Err(e) => println(e.message())
```

Build and test with `novo pkg build` and `novo test tests`.

## What the package contains

| Module | Contents |
| --- | --- |
| `httpsig` | `sign`, `verify`, and the two halves of `verify` (`prepare`, `verify_prepared`), `check_time` and `check_covered`. |
| `hsigtypes` | The message record, the component record, the error codes, and constructors. |
| `hsigmsg` | `request` from a method and a target URI, the cleaning and combining of field lines, the normalised authority, and the query parameters of `@query-param`. |
| `hsigbase` | `component_value` for one component, `signature_params_value`, and `signature_base`. |
| `hsigfields` | Reading and writing `Signature-Input`, `Signature` and `Accept-Signature`, and the typed signature parameters. |
| `hsigalg` | The key types, `sign` and `verify` for a signature base. |

Every `pub` declaration is documented where it is declared, and
[the package's page](https://novo-lang.org/packages/httpsig-nv) is that
reference.

## Algorithms

| `alg` | Sign | Verify | From |
| --- | --- | --- | --- |
| `hmac-sha256` | yes | yes | crypto-nv |
| `ed25519` | yes | yes | ed25519-nv |
| `ecdsa-p256-sha256` | yes | yes | p256-nv |
| `rsa-v1_5-sha256` | NOT IMPLEMENTED | yes | rsa-nv |
| `rsa-pss-sha512` | NOT IMPLEMENTED | NOT IMPLEMENTED | rsa-nv has no SHA-512 |
| `ecdsa-p384-sha384` | NOT IMPLEMENTED | NOT IMPLEMENTED | p256-nv has one curve |

The JSON Web Signature algorithms of RFC 9421 section 3.3.7 are NOT
IMPLEMENTED. A program that needs one of these calls `prepare` to get the
signature base and the signature bytes of a message, and checks them with its
own primitive.

## The rules a user needs

1. **The message is a record the caller fills.** `hsigmsg.request` takes a
   method, an absolute target URI and the header fields. A response is
   `hsigtypes.response` with a status and the header fields. A field with
   several lines is several entries, in the order they occur. The package does
   not read or write HTTP.
2. **A field name is a lower-case string in the covered list.** Names in the
   message are compared without regard to case. A component name that is not
   in lower case is refused (RFC 9421 section 2.1).
3. **Several lines of one field are combined** with a comma and a space, after
   stripping white space and replacing obsolete line folding with one space.
   That is the form a proxy may rewrite, so cover a field only once where the
   application can. `bs` keeps the lines apart.
4. **The package refuses what it cannot resolve.** A covered field that is not
   in the message, an unknown derived component, a parameter that does not
   apply, `bs` with `sf` or `key`, `req` on a request, a Dictionary key or a
   query parameter that is absent, and the same component twice are each an
   `HsigError` with a code, and no signature base is built (section 2.5).
5. **A query parameter that occurs twice is refused.** `@query-param` reads
   one parameter by name, decodes it as `application/x-www-form-urlencoded`,
   and writes it again with every byte but letters, digits and `-._~`
   percent-encoded, so a space is `%20` (section 2.2.8).
6. **`@authority` is normalised**: lower case, without the default port of the
   scheme (section 2.2.3). `@target-uri` uses the authority as given.
7. **`sf` and `key` need the field's Structured Field type.** A table of the
   registered Structured Fields is built in (`Content-Digest`, `Signature`,
   `Client-Cert` and others). A caller adds its own with
   `hsigtypes.with_field_types`. A field of unknown type is an error.
8. **The order is kept.** The covered components and the signature parameters
   are written in the order the caller gives them, and a verifier rebuilds the
   `@signature-params` line from the `Signature-Input` entry in the order it
   has.
9. **A key carries its algorithm.** `alg` in a signature is compared with the
   algorithm of the key and never chooses one (section 3.2, step 6). A
   signature whose `alg` differs from the key's is `HSIG_ERR_ALG_MISMATCH`.
10. **Time is the caller's.** `check_time` takes the current time in seconds
    and a skew. Whether a `created` is recent enough, which `keyid` is
    trusted, and which components must be covered (`check_covered`) are the
    application's decisions (section 3.2.1).
11. **A signature value that does not verify is an error**, not `false`:
    `verify` answers `Err` with `HSIG_ERR_VERIFY_FAILED`. An HMAC is compared
    in constant time.
12. **A value with a line break is refused.** A component value that still has
    a CR or an LF after the folding would let one component look like two lines
    of the base.
13. **A response may cover its request** with the `req` parameter. The caller
    passes the request as the second argument of `sign`, `verify` and
    `prepare`. A `req` component with no request is `HSIG_ERR_NO_REQUEST`.
14. **A key to sign with is the secret, and a key to verify with is the public
    part.** The two are separate types.

## What is not included

- **HTTP.** No parser, no client, no server. The caller reads the fields off
  its own messages and writes the two field values onto the ones it sends.
- **The algorithms marked NOT IMPLEMENTED** in the table above.
- **Key lookup and trust.** A `keyid` is a string the caller maps to a key.
- **Content-Digest.** The digest of a body is another field (RFC 9530). To
  cover the body, compute the digest, put it in a field and cover that field.
- **Replay protection.** `nonce` is carried and returned; remembering the nonces
  seen is the application's.
- **Allocation-free signing on a microcontroller.** A message is a list of
  strings and the base is a string of unbounded length, so no module here
  builds for the embedded tier.

## Related packages

- [sfv-nv](https://novo-lang.org/packages/sfv-nv) is the Structured Field
  syntax that the three fields and the component identifiers are written in.
- [crypto-nv](https://novo-lang.org/packages/crypto-nv),
  [ed25519-nv](https://novo-lang.org/packages/ed25519-nv),
  [p256-nv](https://novo-lang.org/packages/p256-nv) and
  [rsa-nv](https://novo-lang.org/packages/rsa-nv) are the algorithms.
- [jwt-nv](https://novo-lang.org/packages/jwt-nv) signs tokens rather than
  HTTP messages.
- [cookie-nv](https://novo-lang.org/packages/cookie-nv) signs cookie values.

## Tests

The suite is three files under `tests/`.

`tests/appendix_b_tests.nv` holds the test vectors of RFC 9421 as printed:
the example keys of Appendix B.1, the messages of B.2, the signature bases and
fields of B.2.1 to B.2.6, B.3 and B.4, the two signatures of section 4.3, and
the two responses of section 2.4 that cover their requests. The data in the
file is the RFC's text with the line wrapping of RFC 8792 undone. The
signature bases and `Signature-Input` fields of all of them are rebuilt and
compared byte for byte. The signatures are checked as follows.

| Vector | Algorithm | What is checked |
| --- | --- | --- |
| B.2.1, B.2.2, B.2.3 | `rsa-pss-sha512` | base and `Signature-Input` only; the signature is not checked |
| B.2.4 | `ecdsa-p256-sha256` | the RFC's signature verifies; a new one verifies |
| B.2.5 | `hmac-sha256` | the signature made here equals the RFC's bytes |
| B.2.6 | `ed25519` | the signature made here equals the RFC's bytes |
| B.3 | `ecdsa-p256-sha256` | the RFC's signature verifies from the message's own fields |
| B.4 | `ed25519` | the signature holds through three transformations and fails after two |
| 4.3 | `ecdsa-p256-sha256`, `rsa-v1_5-sha256` | both signatures verify among two labels |
| 2.4 | `ecdsa-p256-sha256` | two responses verify against their requests |

`tests/hsig_components_tests.nv` holds the examples of RFC 9421 section 2 for
fields and derived components, and one case for each condition that makes the
signature base fail. `tests/hsig_api_tests.nv` covers the three fields, the
Accept-Signature exchange, the key and signature mistakes, `check_time` and
`check_covered`.

ECDSA signatures in the RFC are not deterministic, so a signature made here is
checked by verifying it.

## Licence

Apache-2.0. See `LICENSE`.
