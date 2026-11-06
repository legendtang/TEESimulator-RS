# Application attestation identity conformance

`ApplicationIdConformanceProbe.java` compares the unminified candidate's actual
`AttestationBuilder.createApplicationId` implementation with Android 13's
`sec_key_att_app_id_provider` Binder service. It runs as keystore UID 1017 and
reads package versions and public signing metadata. It does not initialize the
simulator service, generate keys, read keyboxes or request Play Integrity.

Compile the Java probe with Android SDK stubs, then dex it together with the
candidate's Kotlin/Java classes and runtime dependencies. Stage this isolated
test jar with adb. Do not install it as a module. For example, after staging:

```sh
python tests/android/check-application-id.py --serial DEVICE \
  --classpath /data/local/tmp/tee-application-id-test.jar --uid APP_UID
```

The two modes run in separate processes. The comparator requires exact DER
equality, including package names, versions, digest deduplication and DER set
ordering. Test with a package whose signing certificate has rotated: on the
inspected Android 13 device, the framework reports one compatibility signer,
while `signingCertificateHistory` contains two. Including the whole history
changes the attested application identity.

To test a minified release dex instead, stage that dex and a separate probe jar.
Append `--candidate-class`, `--candidate-method` and `--octets-field` using the
factory and octet storage names from that exact release's R8 mapping. The
factory must be static in this mode. This permits a before/after comparison of
the actual release artifacts without replacing an installed module.

The expected signature source follows AOSP's
`frameworks/base/services/core/java/com/android/server/security/KeyAttestationApplicationIdProviderService.java`:
`GET_SIGNATURES` and `PackageInfo.signatures`. Both the Android 13 release and
the inspected current AOSP branch use this source. The Binder comparison checks
the actual device service instead of inferring its behavior from the source.

A matching application ID proves this local conformance check only. It does not
prove Google accepts an emulated hardware attestation or passes Device integrity.
