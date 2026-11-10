# Changelog

All notable changes to httpsig-nv are recorded here. The format is
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
package follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with the pre-1.0 rule that a breaking change bumps the MINOR number.

## 0.1.0

The first release.

### Added

- **`hsigtypes`**: the message record (`HsigMessage`, a request or a response
  with header and trailer fields), the covered-component record, constructors,
  the table of registered Structured Fields, and the `HSIG_ERR_` codes with
  `HsigError`.
- **`hsigmsg`**: `request` from a method and an absolute target URI, the
  cleaning and combining of field lines, the normalised authority, the
  `@query-param` encoding, and the values of the derived components that come
  straight from the message.
- **`hsigbase`**: `component_value` for one component with the `sf`, `key`,
  `bs`, `tr`, `req` and `name` parameters, `signature_params_value`, and
  `signature_base` by RFC 9421 section 2.5, with each failure of the algorithm
  an `HsigError`.
- **`hsigfields`**: reading and writing the `Signature-Input`, `Signature` and
  `Accept-Signature` fields through sfv-nv, the typed signature parameters
  (`created`, `expires`, `nonce`, `alg`, `keyid`, `tag`), and `fulfil_params`
  for the answer to an Accept-Signature entry.
- **`hsigalg`**: key types that carry their algorithm, and `sign` and `verify`
  for `hmac-sha256`, `ed25519` and `ecdsa-p256-sha256`, and `verify` for
  `rsa-v1_5-sha256`. Ed25519 is verified under the strict rule of ed25519-nv.
- **`httpsig`**: `sign`, `verify`, `prepare` and `verify_prepared`,
  `check_time` and `check_covered`.
- Three test suites. `appendix_b_tests.nv` holds the vectors of RFC 9421
  Appendix B, section 4.3 and section 2.4. `hsig_components_tests.nv` and
  `hsig_api_tests.nv` hold the examples of section 2, the refusals, and the
  API.

### Not included

- `rsa-pss-sha512`, because rsa-nv 0.1.0 hashes with SHA-256 and SHA-384 only.
  The signatures of Appendix B.2.1, B.2.2 and B.2.3 are not checked; their
  signature bases and `Signature-Input` fields are.
- `ecdsa-p384-sha384`, because p256-nv has one curve.
- Signing with `rsa-v1_5-sha256`, because rsa-nv does not sign.
- The JSON Web Signature algorithms of RFC 9421 section 3.3.7.
- An HTTP parser or client, key lookup, and Content-Digest.

### Known

- `sfv-nv` is a path dependency in `novo.toml` until it is published. The
  publish refuses that line and nothing else.
