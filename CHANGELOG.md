# Changelog

## [0.1.12](https://github.com/roquerodrigo/ttlock-ble/compare/v0.1.11...v0.1.12) (2026-08-07)


### Features

* **packaging:** require Python 3.14 ([37a2bc8](https://github.com/roquerodrigo/ttlock-ble/commit/37a2bc833ef26f88d8df3d22a24c1170641fa58b))


### Code Refactoring

* **ble:** move the BLE link out of TTLockClient into its own layer ([3e4d055](https://github.com/roquerodrigo/ttlock-ble/commit/3e4d055543e2f87fef21c336da6ef6989668f315))
* **commands:** decode operate-log tails through a dispatch table ([a5a1402](https://github.com/roquerodrigo/ttlock-ble/commit/a5a1402021cdd2f3edf42ee02fdea615fdd57ccb))


### Miscellaneous Chores

* add an editorconfig ([4a8b21f](https://github.com/roquerodrigo/ttlock-ble/commit/4a8b21f96d7405995594638066965251a26cde9f))

## [0.1.11](https://github.com/roquerodrigo/ttlock-ble/compare/v0.1.10...v0.1.11) (2026-08-07)


### Bug Fixes

* keep command failures inside the public exception hierarchy ([92d31f6](https://github.com/roquerodrigo/ttlock-ble/commit/92d31f6b13a6fbd97190e8aa7a5e5d6b9c956dc4))
* **protocol:** delimit frames by their declared length ([e5ff05e](https://github.com/roquerodrigo/ttlock-ble/commit/e5ff05e38023600d662e23739a287c98cbdf5781)), closes [#55](https://github.com/roquerodrigo/ttlock-ble/issues/55)


### Code Refactoring

* hoist lazy imports and modernize event-loop access ([4332bc5](https://github.com/roquerodrigo/ttlock-ble/commit/4332bc542016c445f1c66fc433d12c14ee9bcfa3))
* split the command layer into one module per command family ([3a98492](https://github.com/roquerodrigo/ttlock-ble/commit/3a98492cf26d6b9805196302821c045b145b07cd))


### Documentation

* align CODE_STYLE, README, and docstrings with the actual project ([1bffa02](https://github.com/roquerodrigo/ttlock-ble/commit/1bffa02f16067549d7087fa52aca40494bdf1d8a))


### Build System

* keep development assets out of the source distribution ([8052641](https://github.com/roquerodrigo/ttlock-ble/commit/8052641738d0cdd89ceef7169169a5d7578dd2c5))


### Continuous Integration

* run checks on pull requests targeting any branch ([bba7bf5](https://github.com/roquerodrigo/ttlock-ble/commit/bba7bf57a2d6039bc3b555a08ed5566a959602fe))
* run code scanning on pull requests targeting any branch ([eac9ba0](https://github.com/roquerodrigo/ttlock-ble/commit/eac9ba0e8c65e7857e3a3b8c41b73479abd2629b))


### Tests

* replace captured fixtures with synthetic credentials ([bb91906](https://github.com/roquerodrigo/ttlock-ble/commit/bb91906262dd60af415617fc9d09a5e549aa04e7))
* share the VirtualKey fixture through conftest ([6f3098b](https://github.com/roquerodrigo/ttlock-ble/commit/6f3098bf6c52a6fd8f721893b86a2571bc337457))


### Miscellaneous Chores

* consolidate packaging metadata and tool configuration ([102912c](https://github.com/roquerodrigo/ttlock-ble/commit/102912c189b33354aff14fab5190851ca6822a70))
* enforce top-level imports outside the test tree ([b3d50cd](https://github.com/roquerodrigo/ttlock-ble/commit/b3d50cdd7aec85b2f2bd2fe1a38a6f1f619dc3a3))
* keep the test-local import exemption ([5a4e710](https://github.com/roquerodrigo/ttlock-ble/commit/5a4e71090788fe7df32fe19ed7f61595b94c37cd))
* tighten and scope the lint and type-check configuration ([1e32d88](https://github.com/roquerodrigo/ttlock-ble/commit/1e32d889aeb99ecfc0ac901a72068bf19c9624b0))

## [0.1.10](https://github.com/roquerodrigo/ttlock-ble/compare/v0.1.9...v0.1.10) (2026-08-05)


### Bug Fixes

* **client:** match the echoed opcode inside the payload, not the frame byte ([9523e54](https://github.com/roquerodrigo/ttlock-ble/commit/9523e54cdf1501e31868b2b7c6e6f69f9fd50ec1))

## [0.1.9](https://github.com/roquerodrigo/ttlock-ble/compare/v0.1.8...v0.1.9) (2026-08-05)


### Bug Fixes

* **client:** match the echoed opcode before accepting a reply ([b2f14cc](https://github.com/roquerodrigo/ttlock-ble/commit/b2f14cc2185e8713ed3758b4fb12f18b22b9749b))


### Dependencies

* **deps:** bump the python-deps group across 1 directory with 2 updates ([3105d90](https://github.com/roquerodrigo/ttlock-ble/commit/3105d90ee082de06f5cedad8b66b7295ec55b6d8))


### Continuous Integration

* refresh the lockfile through the release workflow ([6b57932](https://github.com/roquerodrigo/ttlock-ble/commit/6b579321896614c1a32a463a1ace17527c679811))


### Miscellaneous Chores

* **deps-dev:** bump ruff to 0.16.0 ([1955ffe](https://github.com/roquerodrigo/ttlock-ble/commit/1955ffe35850c290e891e924d346f6cb48f15a07))
* **deps:** bump the python-deps group across 1 directory with 3 updates ([6b3ea1f](https://github.com/roquerodrigo/ttlock-ble/commit/6b3ea1fa988d389fc5e8adc0751674b2b209f76f))
* move CI to the shared workflows repository ([ee9299a](https://github.com/roquerodrigo/ttlock-ble/commit/ee9299a3956e32c3ddbbe8d3caa943d19a4f4c04))
* release on every conventional commit type ([014c066](https://github.com/roquerodrigo/ttlock-ble/commit/014c066df40980880ef89c2d722d1236e3b89cad))

## [0.1.8](https://github.com/roquerodrigo/ttlock-ble/compare/v0.1.7...v0.1.8) (2026-07-29)


### Features

* **models:** decode lock state from BLE advertisements ([75a3601](https://github.com/roquerodrigo/ttlock-ble/commit/75a36018955d8671046bbd8e32721cf748c497dc))


### Documentation

* update CLAUDE.md ([2be577a](https://github.com/roquerodrigo/ttlock-ble/commit/2be577abcbd53a6a1f3c696e59de67f2801ea48f))

## [0.1.7](https://github.com/roquerodrigo/ttlock-ble/compare/v0.1.6...v0.1.7) (2026-05-25)


### Documentation

* add README and MIT LICENSE ([c1d8e84](https://github.com/roquerodrigo/ttlock-ble/commit/c1d8e8480039e20a25686444ece7813a7975d9be))

## [0.1.6](https://github.com/roquerodrigo/ttlock-ble/compare/v0.1.5...v0.1.6) (2026-05-24)


### Features

* **client:** add sync_time and get_lock_time for drift-aware RTC sync ([f850ed2](https://github.com/roquerodrigo/ttlock-ble/commit/f850ed2f7c61b565d0f5d30254138817c2ea8776))


### Bug Fixes

* **deps:** split lint group from dev (matches reusable workflow) ([7246328](https://github.com/roquerodrigo/ttlock-ble/commit/72463288b0a35ebb4e52b137c305ad010715906d))
* set mypy default files=src + lower cov-fail-under to 60% (actual 63%) ([6a65f7a](https://github.com/roquerodrigo/ttlock-ble/commit/6a65f7a356d88edb81ba9a62738fa0a96bed7879))

## [0.1.5](https://github.com/roquerodrigo/ttlock-ble/compare/v0.1.4...v0.1.5) (2026-05-18)


### Features

* **models:** parse lock-event and log-entry dates as datetime; add ResponseStatus enum ([389b702](https://github.com/roquerodrigo/ttlock-ble/commit/389b702831c5bdcb19c5af832b8ea8dcbb4e8bd6))

## [0.1.4](https://github.com/roquerodrigo/ttlock-ble/compare/v0.1.3...v0.1.4) (2026-05-17)


### Bug Fixes

* **deps:** relax dependency pins for Home Assistant compatibility ([8105f09](https://github.com/roquerodrigo/ttlock-ble/commit/8105f09f915155c7a00a67174dcfe33d35a2cc1a))

## [0.1.3](https://github.com/roquerodrigo/ttlock-ble/compare/v0.1.2...v0.1.3) (2026-05-17)


### Features

* **scripts:** add dump_operation_log CLI for offline log inspection ([8fca91b](https://github.com/roquerodrigo/ttlock-ble/commit/8fca91b23db43c018ee8a933f61322ad23a6b561))


### Bug Fixes

* **client:** paginate operation log via response cursor; decode full record-type catalog ([20aa051](https://github.com/roquerodrigo/ttlock-ble/commit/20aa0514f9f124025d4b1ac051c8e5007e3f8d68))

## [0.1.2](https://github.com/roquerodrigo/ttlock-ble/compare/v0.1.1...v0.1.2) (2026-05-11)


### Features

* **client:** decode the two cmd_echo=0x14 push variants ([63097c9](https://github.com/roquerodrigo/ttlock-ble/commit/63097c978fac1206409065ae8c98899f629a5df8))
* **client:** post-command keep-alive in the SDK ([ba2c291](https://github.com/roquerodrigo/ttlock-ble/commit/ba2c2911d5e52929100c53e97f3073388c076de5))


### Bug Fixes

* **client:** wrap asyncio.TimeoutError in _exchange as TTLockError ([1547c3a](https://github.com/roquerodrigo/ttlock-ble/commit/1547c3a3f47536c1260064a86100751c0dfd2cfe))
* **cloud:** defer load_uniqueid to first async use ([0b4975e](https://github.com/roquerodrigo/ttlock-ble/commit/0b4975edda90acf4608bbae1a264b65ca7bd678a))

## [0.1.1](https://github.com/roquerodrigo/ttlock-ble/compare/v0.1.0...v0.1.1) (2026-05-11)


### Features

* initial release of ttlock-ble Python SDK ([408a778](https://github.com/roquerodrigo/ttlock-ble/commit/408a778cd3dd067a09f892373b852ad87e418e68))
