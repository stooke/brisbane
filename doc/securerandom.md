# Sourcing cryptographically secure random bits

This document describes how the `com.oracle.jipher` module sources cryptographically secure random bits in accordance with [NIST SP 800-90A](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final)

In short, Jipher defers to OpenSSL's FIPS RBG for Jipher cryptographic operations. A `SecureRandom` supplied to `init`, `initialize`, or `newEncapsulator` is accepted for Java API compatibility but ignored as a source of random bytes.

`SecureRandom.getInstance("DRBG", "JipherJCE")` also obtains bytes from the OpenSSL FIPS RBG.

## What happens to a supplied SecureRandom

For any Java Cryptography API calls to the JipherJCE provider, listed below, the `SecureRandom` argument is ignored as a source of random bytes:

- `Cipher.init(..., SecureRandom)`
- `KeyPairGenerator.initialize(..., SecureRandom)`
- `Signature.initSign(..., SecureRandom)`
- `KeyGenerator.init(..., SecureRandom)`
- `AlgorithmParameterGenerator.init(..., SecureRandom)`
- `KeyAgreement.init(..., SecureRandom)`
- `KEM.newEncapsulator(..., SecureRandom)`

For example, this code does **not** make Jipher use `testRandom`:

```java
Signature signature = Signature.getInstance("RSASSA-PSS", "JipherJCE");
...
signature.initSign(privateKey, testRandom);
```

`testRandom` is ignored; any random bytes required by the RSA signing operation come from OpenSSL. The same applies whether `testRandom` is a Jipher `SecureRandom`, a standard-JDK implementation, or a deterministic test double. Do not rely on using a SecureRandom that a produces a repeatable deterministic series of bits for application testing.

The Java Cryptography API specifies that API calls which do not accept a `SecureRandom` argument, but nonetheless require a source of random bytes, obtain randomness as follows:

>using the SecureRandom implementation of the highest-priority installed provider as the source of randomness. (If none of the installed providers supplies an implementation of SecureRandom, a system-provided source of randomness will be used.)

The JipherJCE provider deviates from this specified behavior. When an API call implemented by JipherJCE requires random bytes and no `SecureRandom` instance is supplied, it uses an internal OpenSSL DRBG rather than a `SecureRandom` provided by the highest-priority installed provider.

## Motivation

There are two motivations for this:

**(1)** FIPS compliance issues:
* Approved RBGs are defined in [SP 800-90A: Recommendation for Random Number Generation Using Deterministic Random Bit Generators]((https://csrc.nist.gov/pubs/sp/800/90/a/r1/final))
* The required security strength for RBGs is defined in several NIST documents including [NIST SP 800-133 Revision 2: Recommendation for Cryptographic Key Generation](https://csrc.nist.gov/pubs/sp/800/133/r2/final)

Jipher must guarantee that it only uses a FIPS-approved RBG that provides sufficient security strength.

**(2)** Performance issues:
* Cryptographic functionality provided by JipherJCE classes is, behind the scenes, delivered by the OpenSSL FIPS module
* A performance benefit is derived by having OpenSSL use the FIPS module's own native DRBG for all internal operations

Configuring an OpenSSL algorithm instance to instead use a specific Java SecureRandom instance as a source of randomness is incompatible with the way OpenSSL's RNG infrastructure is designed. The performance cost of creating a bridge is not justified by any limited benefits it may provide.

## Where Jipher SecureRandom bytes come from

Jipher registers one `SecureRandom` algorithm: `DRBG`. Its SPI delegates `nextBytes` and `generateSeed` to Jipher's `Rand.generate`, which calls OpenSSL `randBytes` at a requested strength of 256 bits. This means that:

```java
SecureRandom random = SecureRandom.getInstance("DRBG", "JipherJCE");
random.nextBytes(bytes);
```

fills `bytes` using the OpenSSL random subsystem in Jipher's library context. It is not a Java-side DRBG with Java-visible state.

`random.setSeed(...)` is accepted but has no effect: Jipher's `SecureRandomSpi.engineSetSeed` is intentionally a no-op. In particular, seeding a Jipher `SecureRandom` cannot make either that instance or an OpenSSL-backed Jipher operation reproducible.

### OpenSSL DRBG

OpenSSL internally manages a DRBG hierarchy used by operations requiring a source of randomness. The configured DRBG algorithm will be one of the following, configured with 256-bit security strength:

* CTR-DRBG
* HASH-DRBG
* HMAC-DRBG

OpenSSL uses a per-thread DRBG seeded from a global DRBG. Entropy for the global DRBG is obtained from the operating system and both global and per-thread DRBGs are automatically reseeded according to configured call-count and time intervals. These are OpenSSL configuration, not per-instance Java `SecureRandom` settings.

More details can be found in the [OpenSSL RAND man page](https://docs.openssl.org/master/man7/RAND/) or [FIPS provider documentation](https://docs.openssl.org/3.5/man7/OSSL_PROVIDER-FIPS/#random-number-generation)

## Unsupported Java DRBG controls

Jipher does not bridge Java's post-JDK-8 parameterized `SecureRandom` APIs to OpenSSL.

| Operation | Jipher behavior |
|---|---|
| `SecureRandom.getInstance("DRBG", params, "JipherJCE")` | Throws `NoSuchAlgorithmException`; Jipher's SPI cannot be constructed with parameters. |
| `random.getParameters()` | Returns `null`. |
| `random.nextBytes(bytes, params)` | Throws `UnsupportedOperationException`. |
| `random.reseed()` | Throws `UnsupportedOperationException`. |
| `random.reseed(params)` | Throws `UnsupportedOperationException`. |

Calling `SecureRandom.getInstance(algorithm, params)` without naming Jipher may select another installed provider that supports the requested parameters. That instance remains a Java-side random source; passing it to a Jipher service still does not alter the OpenSSL source used by that service.

## Development and test guidance

- Use Jipher `SecureRandom` when an application directly needs random bytes produced by Jipher's OpenSSL-backed random subsystem.
- It is preferable to use JCA initialization APIs which do not specify a `SecureRandom` when possible, rather than passing `null` or a subsequently ignored object.
- Do not use a deterministic `SecureRandom` injection to make a Jipher operation repeatable. Assert externally observable properties instead, or use a dedicated Jipher/OpenSSL test facility if one is provided.
