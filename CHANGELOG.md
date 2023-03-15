# Changelog

## [0.15.0](https://github.com/parallaxsecond/parsec-client-rust/tree/0.15.0) (2023-01-04)

[Full Changelog](https://github.com/parallaxsecond/parsec-client-rust/compare/0.14.1...0.15.0)

**Merged pull requests:**

- Update to remove const\_err [\#107](https://github.com/parallaxsecond/parsec-client-rust/pull/107) ([marcsvll](https://github.com/marcsvll))

## [0.14.1](https://github.com/parallaxsecond/parsec-client-rust/tree/0.14.1) (2022-09-12)

[Full Changelog](https://github.com/parallaxsecond/parsec-client-rust/compare/0.14.0...0.14.1)

**Merged pull requests:**

- Bump Crates' versions [\#105](https://github.com/parallaxsecond/parsec-client-rust/pull/105) ([mohamedasaker-arm](https://github.com/mohamedasaker-arm))
- Build parse-interface with deprecated primitive feature changes [\#104](https://github.com/parallaxsecond/parsec-client-rust/pull/104) ([mohamedasaker-arm](https://github.com/mohamedasaker-arm))

## [0.14.0](https://github.com/parallaxsecond/parsec-client-rust/tree/0.14.0) (2022-02-15)

[Full Changelog](https://github.com/parallaxsecond/parsec-client-rust/compare/0.13.0...0.14.0)

**Implemented enhancements:**

- Add activate credential attestation methods [\#100](https://github.com/parallaxsecond/parsec-client-rust/pull/100) ([ionut-arm](https://github.com/ionut-arm))

**Merged pull requests:**

- Prepare for new version of client [\#102](https://github.com/parallaxsecond/parsec-client-rust/pull/102) ([ionut-arm](https://github.com/ionut-arm))
- Add PsaCipherEncrypt and PsaCipherDecrypt operations [\#101](https://github.com/parallaxsecond/parsec-client-rust/pull/101) ([akazimierskigl](https://github.com/akazimierskigl))
- Merge can-do-crypto branch into main [\#98](https://github.com/parallaxsecond/parsec-client-rust/pull/98) ([anta5010](https://github.com/anta5010))
- Use the main branch of Parsec-interface [\#97](https://github.com/parallaxsecond/parsec-client-rust/pull/97) ([anta5010](https://github.com/anta5010))
- Merge origin/main into can-do-crypto  [\#96](https://github.com/parallaxsecond/parsec-client-rust/pull/96) ([anta5010](https://github.com/anta5010))
- Use Parsec Mock for testing [\#95](https://github.com/parallaxsecond/parsec-client-rust/pull/95) ([hug-dev](https://github.com/hug-dev))
- Bump prost and spiffe for cargo-audit [\#94](https://github.com/parallaxsecond/parsec-client-rust/pull/94) ([hug-dev](https://github.com/hug-dev))
- Added CanDoCrypto to basic client. [\#93](https://github.com/parallaxsecond/parsec-client-rust/pull/93) ([Kakemone](https://github.com/Kakemone))
- Update CHANGELOG [\#92](https://github.com/parallaxsecond/parsec-client-rust/pull/92) ([hug-dev](https://github.com/hug-dev))

## [0.13.0](https://github.com/parallaxsecond/parsec-client-rust/tree/0.13.0) (2021-08-04)

[Full Changelog](https://github.com/parallaxsecond/parsec-client-rust/compare/0.12.0...0.13.0)

**Implemented enhancements:**

- Use &str for key names instead of String [\#81](https://github.com/parallaxsecond/parsec-client-rust/issues/81)
- Investigate a SignClient for just-in-time key creation [\#70](https://github.com/parallaxsecond/parsec-client-rust/issues/70)
- Modify interface to take parameters as reference [\#31](https://github.com/parallaxsecond/parsec-client-rust/issues/31)
- Add SPIFFE authentication via the new crate [\#85](https://github.com/parallaxsecond/parsec-client-rust/pull/85) ([hug-dev](https://github.com/hug-dev))

**Fixed bugs:**

- Change Codecov badge to main branch [\#89](https://github.com/parallaxsecond/parsec-client-rust/pull/89) ([ionut-arm](https://github.com/ionut-arm))

**Merged pull requests:**

- Prepare for the release [\#90](https://github.com/parallaxsecond/parsec-client-rust/pull/90) ([hug-dev](https://github.com/hug-dev))
- Add cargo-audit config file. [\#88](https://github.com/parallaxsecond/parsec-client-rust/pull/88) ([ionut-arm](https://github.com/ionut-arm))
- Changed to use &str for key\_name parameters. [\#86](https://github.com/parallaxsecond/parsec-client-rust/pull/86) ([MattDavis00](https://github.com/MattDavis00))
- Update psa-crypto [\#84](https://github.com/parallaxsecond/parsec-client-rust/pull/84) ([hug-dev](https://github.com/hug-dev))
- Support for ps\_sign\_ and ps\_verify\_message Parsec operations. [\#83](https://github.com/parallaxsecond/parsec-client-rust/pull/83) ([RobertDrazkowskiGL](https://github.com/RobertDrazkowskiGL))
- Add dependency on the newest \(git only at the moment\) parsec-interface. [\#82](https://github.com/parallaxsecond/parsec-client-rust/pull/82) ([RobertDrazkowskiGL](https://github.com/RobertDrazkowskiGL))
- Add the CHANGELOG [\#80](https://github.com/parallaxsecond/parsec-client-rust/pull/80) ([hug-dev](https://github.com/hug-dev))

## [0.12.0](https://github.com/parallaxsecond/parsec-client-rust/tree/0.12.0) (2021-03-18)

[Full Changelog](https://github.com/parallaxsecond/parsec-client-rust/compare/0.11.0...0.12.0)

**Implemented enhancements:**

- Implement component bootstrapping [\#52](https://github.com/parallaxsecond/parsec-client-rust/issues/52)
- Resolve service endpoint from a URI environment variable [\#37](https://github.com/parallaxsecond/parsec-client-rust/issues/37)
- Add code coverage checking to the nightly run [\#77](https://github.com/parallaxsecond/parsec-client-rust/pull/77) ([ionut-arm](https://github.com/ionut-arm))
- Bootstrap socket location from env variable [\#73](https://github.com/parallaxsecond/parsec-client-rust/pull/73) ([ionut-arm](https://github.com/ionut-arm))
- Increase the default timeout to 60 seconds [\#72](https://github.com/parallaxsecond/parsec-client-rust/pull/72) ([hug-dev](https://github.com/hug-dev))
- Add changelog file [\#60](https://github.com/parallaxsecond/parsec-client-rust/pull/60) ([ionut-arm](https://github.com/ionut-arm))

**Closed issues:**

- Add support for ListClients and DeleteClient [\#66](https://github.com/parallaxsecond/parsec-client-rust/issues/66)
- Add a JWT-SVID authentication data [\#55](https://github.com/parallaxsecond/parsec-client-rust/issues/55)

**Merged pull requests:**

- Prepare for version 0.12.0 [\#79](https://github.com/parallaxsecond/parsec-client-rust/pull/79) ([hug-dev](https://github.com/hug-dev))
- Update the interface to latest master [\#78](https://github.com/parallaxsecond/parsec-client-rust/pull/78) ([hug-dev](https://github.com/hug-dev))
- Update hash to latest interface [\#76](https://github.com/parallaxsecond/parsec-client-rust/pull/76) ([hug-dev](https://github.com/hug-dev))
- Move a log message from info to debug [\#75](https://github.com/parallaxsecond/parsec-client-rust/pull/75) ([hug-dev](https://github.com/hug-dev))
- Add documentation about the endpoint env. var. [\#74](https://github.com/parallaxsecond/parsec-client-rust/pull/74) ([hug-dev](https://github.com/hug-dev))
- Update interface dependency [\#71](https://github.com/parallaxsecond/parsec-client-rust/pull/71) ([ionut-arm](https://github.com/ionut-arm))
- Remove spiffe-based feature from master [\#68](https://github.com/parallaxsecond/parsec-client-rust/pull/68) ([hug-dev](https://github.com/hug-dev))
- Add ListClients and DeleteClient operations [\#67](https://github.com/parallaxsecond/parsec-client-rust/pull/67) ([hug-dev](https://github.com/hug-dev))
- Disable Travis CI build [\#65](https://github.com/parallaxsecond/parsec-client-rust/pull/65) ([ionut-arm](https://github.com/ionut-arm))
- Consume parsec-interface at 0.22.0 and bump crate to 0.12.0 [\#63](https://github.com/parallaxsecond/parsec-client-rust/pull/63) ([paulhowardarm](https://github.com/paulhowardarm))
- Add a note about JWT-SVID Workload Endpoint [\#62](https://github.com/parallaxsecond/parsec-client-rust/pull/62) ([hug-dev](https://github.com/hug-dev))
- Add a JWT-SVID authentication method [\#61](https://github.com/parallaxsecond/parsec-client-rust/pull/61) ([hug-dev](https://github.com/hug-dev))

## [0.11.0](https://github.com/parallaxsecond/parsec-client-rust/tree/0.11.0) (2020-10-20)

[Full Changelog](https://github.com/parallaxsecond/parsec-client-rust/compare/0.10.0...0.11.0)

**Implemented enhancements:**

- Implement provider and auth bootstrapping [\#58](https://github.com/parallaxsecond/parsec-client-rust/pull/58) ([ionut-arm](https://github.com/ionut-arm))
- Add Unix Peer Credential auth support [\#57](https://github.com/parallaxsecond/parsec-client-rust/pull/57) ([ionut-arm](https://github.com/ionut-arm))
- Remove filesystem checks [\#56](https://github.com/parallaxsecond/parsec-client-rust/pull/56) ([ionut-arm](https://github.com/ionut-arm))

**Fixed bugs:**

- Socket path security checks can fail when the client is in a container [\#51](https://github.com/parallaxsecond/parsec-client-rust/issues/51)

**Closed issues:**

- Implement new authenticator support [\#41](https://github.com/parallaxsecond/parsec-client-rust/issues/41)

**Merged pull requests:**

- Add a new construction for naked client [\#59](https://github.com/parallaxsecond/parsec-client-rust/pull/59) ([hug-dev](https://github.com/hug-dev))
- Quickfix: replace parsec-interface patch with a direct dependency [\#54](https://github.com/parallaxsecond/parsec-client-rust/pull/54) ([joechrisellis](https://github.com/joechrisellis))
- Add ListKeys support [\#53](https://github.com/parallaxsecond/parsec-client-rust/pull/53) ([joechrisellis](https://github.com/joechrisellis))

## [0.10.0](https://github.com/parallaxsecond/parsec-client-rust/tree/0.10.0) (2020-10-02)

[Full Changelog](https://github.com/parallaxsecond/parsec-client-rust/compare/0.9.0...0.10.0)

## [0.9.0](https://github.com/parallaxsecond/parsec-client-rust/tree/0.9.0) (2020-09-07)

[Full Changelog](https://github.com/parallaxsecond/parsec-client-rust/compare/0.8.0...0.9.0)

**Implemented enhancements:**

- Manage data safely within the client [\#9](https://github.com/parallaxsecond/parsec-client-rust/issues/9)
- Upgrade dependencies versions [\#48](https://github.com/parallaxsecond/parsec-client-rust/pull/48) ([hug-dev](https://github.com/hug-dev))

## [0.8.0](https://github.com/parallaxsecond/parsec-client-rust/tree/0.8.0) (2020-08-18)

[Full Changelog](https://github.com/parallaxsecond/parsec-client-rust/compare/0.7.1...0.8.0)

**Implemented enhancements:**

- Added has compute and compare [\#45](https://github.com/parallaxsecond/parsec-client-rust/pull/45) ([sbailey-arm](https://github.com/sbailey-arm))

**Merged pull requests:**

- Add test for psa\_generate\_random [\#47](https://github.com/parallaxsecond/parsec-client-rust/pull/47) ([joechrisellis](https://github.com/joechrisellis))
- Added raw key agreement and test [\#46](https://github.com/parallaxsecond/parsec-client-rust/pull/46) ([sbailey-arm](https://github.com/sbailey-arm))
- Added aead encrypt and decrypt [\#44](https://github.com/parallaxsecond/parsec-client-rust/pull/44) ([sbailey-arm](https://github.com/sbailey-arm))
- Add support for ListAuthenticators operation [\#43](https://github.com/parallaxsecond/parsec-client-rust/pull/43) ([joechrisellis](https://github.com/joechrisellis))
- Add Rust client support for `psa_generate_random` operation [\#42](https://github.com/parallaxsecond/parsec-client-rust/pull/42) ([joechrisellis](https://github.com/joechrisellis))

## [0.7.1](https://github.com/parallaxsecond/parsec-client-rust/tree/0.7.1) (2020-07-22)

[Full Changelog](https://github.com/parallaxsecond/parsec-client-rust/compare/0.7.0...0.7.1)

**Implemented enhancements:**

- Publish a new version [\#40](https://github.com/parallaxsecond/parsec-client-rust/pull/40) ([hug-dev](https://github.com/hug-dev))
- Implement `Error` and `Display` traits for `parsec_client::error::Error` [\#39](https://github.com/parallaxsecond/parsec-client-rust/pull/39) ([joechrisellis](https://github.com/joechrisellis))

## [0.7.0](https://github.com/parallaxsecond/parsec-client-rust/tree/0.7.0) (2020-07-15)

[Full Changelog](https://github.com/parallaxsecond/parsec-client-rust/compare/0.6.0...0.7.0)

**Implemented enhancements:**

- Added PsaExportKey [\#38](https://github.com/parallaxsecond/parsec-client-rust/pull/38) ([sbailey-arm](https://github.com/sbailey-arm))

## [0.6.0](https://github.com/parallaxsecond/parsec-client-rust/tree/0.6.0) (2020-07-07)

[Full Changelog](https://github.com/parallaxsecond/parsec-client-rust/compare/0.5.0...0.6.0)

**Merged pull requests:**

- Added asymmetric encrypt and decrypt [\#36](https://github.com/parallaxsecond/parsec-client-rust/pull/36) ([sbailey-arm](https://github.com/sbailey-arm))

## [0.5.0](https://github.com/parallaxsecond/parsec-client-rust/tree/0.5.0) (2020-07-02)

[Full Changelog](https://github.com/parallaxsecond/parsec-client-rust/compare/0.4.0...0.5.0)

**Implemented enhancements:**

- Add memory wiping functionality [\#32](https://github.com/parallaxsecond/parsec-client-rust/pull/32) ([ionut-arm](https://github.com/ionut-arm))

**Fixed bugs:**

- Fix the fs check on the socket folder feature [\#35](https://github.com/parallaxsecond/parsec-client-rust/pull/35) ([hug-dev](https://github.com/hug-dev))
- Import the newer interface [\#34](https://github.com/parallaxsecond/parsec-client-rust/pull/34) ([hug-dev](https://github.com/hug-dev))

**Merged pull requests:**

- Change socket location and add checks [\#33](https://github.com/parallaxsecond/parsec-client-rust/pull/33) ([hug-dev](https://github.com/hug-dev))

## [0.4.0](https://github.com/parallaxsecond/parsec-client-rust/tree/0.4.0) (2020-06-05)

[Full Changelog](https://github.com/parallaxsecond/parsec-client-rust/compare/0.3.0...0.4.0)

**Implemented enhancements:**

- Import the newest interface and increase version [\#30](https://github.com/parallaxsecond/parsec-client-rust/pull/30) ([hug-dev](https://github.com/hug-dev))
- Import the new interface [\#29](https://github.com/parallaxsecond/parsec-client-rust/pull/29) ([hug-dev](https://github.com/hug-dev))

## [0.3.0](https://github.com/parallaxsecond/parsec-client-rust/tree/0.3.0) (2020-05-06)

[Full Changelog](https://github.com/parallaxsecond/parsec-client-rust/compare/0.2.0...0.3.0)

**Implemented enhancements:**

- Expose the interface through the client, even for testing [\#25](https://github.com/parallaxsecond/parsec-client-rust/issues/25)
- Add Send and Sync to trait objects [\#27](https://github.com/parallaxsecond/parsec-client-rust/pull/27) ([hug-dev](https://github.com/hug-dev))

## [0.2.0](https://github.com/parallaxsecond/parsec-client-rust/tree/0.2.0) (2020-04-24)

[Full Changelog](https://github.com/parallaxsecond/parsec-client-rust/compare/0.1.0...0.2.0)

**Implemented enhancements:**

- Resurface full interface as part of core [\#26](https://github.com/parallaxsecond/parsec-client-rust/pull/26) ([ionut-arm](https://github.com/ionut-arm))

## [0.1.0](https://github.com/parallaxsecond/parsec-client-rust/tree/0.1.0) (2020-04-22)

[Full Changelog](https://github.com/parallaxsecond/parsec-client-rust/compare/a574ae6083652a7dd57e5e99fbadd05a423143fc...0.1.0)

**Implemented enhancements:**

- Make the CoreClient really dumb [\#19](https://github.com/parallaxsecond/parsec-client-rust/issues/19)
- Extract UnixSocket-specific functionality out of RequestHandler [\#13](https://github.com/parallaxsecond/parsec-client-rust/issues/13)
- Create test framework [\#7](https://github.com/parallaxsecond/parsec-client-rust/issues/7)
- Implement client-specific error structures [\#5](https://github.com/parallaxsecond/parsec-client-rust/issues/5)
- Implement configuration [\#3](https://github.com/parallaxsecond/parsec-client-rust/issues/3)
- Add methods for modifying timeout of IPC handlers [\#24](https://github.com/parallaxsecond/parsec-client-rust/pull/24) ([ionut-arm](https://github.com/ionut-arm))
- Make `implicit_provider` optional [\#23](https://github.com/parallaxsecond/parsec-client-rust/pull/23) ([ionut-arm](https://github.com/ionut-arm))
- Add getters for auth\_data and implicit\_provider [\#22](https://github.com/parallaxsecond/parsec-client-rust/pull/22) ([ionut-arm](https://github.com/ionut-arm))
- Add contributing guidelines link [\#21](https://github.com/parallaxsecond/parsec-client-rust/pull/21) ([hug-dev](https://github.com/hug-dev))
- Refactor low level clients [\#20](https://github.com/parallaxsecond/parsec-client-rust/pull/20) ([ionut-arm](https://github.com/ionut-arm))
- Add failing IPC test [\#15](https://github.com/parallaxsecond/parsec-client-rust/pull/15) ([ionut-arm](https://github.com/ionut-arm))
- Factor IPC handling out of the request handler [\#14](https://github.com/parallaxsecond/parsec-client-rust/pull/14) ([ionut-arm](https://github.com/ionut-arm))
- Add testing framework and unit tests [\#12](https://github.com/parallaxsecond/parsec-client-rust/pull/12) ([ionut-arm](https://github.com/ionut-arm))
- Make inner attributes configurable [\#10](https://github.com/parallaxsecond/parsec-client-rust/pull/10) ([ionut-arm](https://github.com/ionut-arm))
- Add client-specific error types [\#8](https://github.com/parallaxsecond/parsec-client-rust/pull/8) ([ionut-arm](https://github.com/ionut-arm))
- Seed initial client [\#1](https://github.com/parallaxsecond/parsec-client-rust/pull/1) ([ionut-arm](https://github.com/ionut-arm))

**Closed issues:**

- Rename methods to contain `psa_` prefix [\#17](https://github.com/parallaxsecond/parsec-client-rust/issues/17)
- Improve documentation [\#2](https://github.com/parallaxsecond/parsec-client-rust/issues/2)

**Merged pull requests:**

- Add "psa\_" prefix to method names. [\#18](https://github.com/parallaxsecond/parsec-client-rust/pull/18) ([ionut-arm](https://github.com/ionut-arm))
- Add documentation [\#16](https://github.com/parallaxsecond/parsec-client-rust/pull/16) ([ionut-arm](https://github.com/ionut-arm))
- Update the way copyrights are displayed [\#11](https://github.com/parallaxsecond/parsec-client-rust/pull/11) ([ionut-arm](https://github.com/ionut-arm))



\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
