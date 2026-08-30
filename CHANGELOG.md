# Changelog

## [0.3.0](https://github.com/roquerodrigo/ttlock-ble/compare/v0.2.2...v0.3.0) (2026-08-30)


### ⚠ BREAKING CHANGES

* **client:** `calibrate_time()` takes a required `local_time` argument where `when` was optional and defaulted to UTC; `sync_time()`'s `when=` keyword is likewise now a required `local_time=`; `payload_time_calibrate()` requires its argument. Callers relying on the default must pass the lock's local time explicitly - passing UTC to a lock that keeps local time moves its clock by the offset.
* **client:** `get_auto_lock_time()` and `set_auto_lock_time()` now raise `TTLockError` when the lock rejects the request, where before both returned quietly and `get_auto_lock_time()` answered `-1`. Callers that branched on `-1` to detect a failure must catch `TTLockError` instead. `parse_auto_lock_response()` raises `RuntimeError` on a FAILED status and `ValueError` on a truncated payload for the same reason.

### Features

* **cli:** add auto-lock delay commands ([4544811](https://github.com/roquerodrigo/ttlock-ble/commit/45448112d6a49d9c0c5148596e642d28bf682b37))
* **cli:** add keypad passcode commands ([e784d45](https://github.com/roquerodrigo/ttlock-ble/commit/e784d45984d1bc6d7e79fedf8e4c36108c81a087))
* **client:** add get_auto_lock_limits() ([1b08a5b](https://github.com/roquerodrigo/ttlock-ble/commit/1b08a5b32ce906c77a48bc4b6457d4c16e77c7ed))


### Bug Fixes

* **client:** require admin handshake for auto-lock commands ([d13a746](https://github.com/roquerodrigo/ttlock-ble/commit/d13a7469c7df88f0d341cddf87e3bc5536825a38))
* **client:** require admin handshake for keyboard-password commands ([d1f1ccb](https://github.com/roquerodrigo/ttlock-ble/commit/d1f1ccb1853940f48906734b0443c8dd427f56d0))
* **client:** require admin handshake to write the lock's clock ([58c1fc1](https://github.com/roquerodrigo/ttlock-ble/commit/58c1fc140e5fa03b63b50b3a0a8a700da2934826))
* **packaging:** normalize path separators in sdist tests on Windows ([9d6e149](https://github.com/roquerodrigo/ttlock-ble/commit/9d6e14953a20319e8e02e690010f23b768c90469))

## [0.2.2](https://github.com/roquerodrigo/ttlock-ble/compare/v0.2.1...v0.2.2) (2026-08-26)


### Features

* **client:** read device info from the standard BLE Device Information Service ([69d719a](https://github.com/roquerodrigo/ttlock-ble/commit/69d719ae2f04d8c3600ba75f31e0038447adc513))


### Documentation

* **models:** record the second lock the device info fields were confirmed on ([21e4fa4](https://github.com/roquerodrigo/ttlock-ble/commit/21e4fa492289ec78b01be09dcf1c9027522ccac2))

## [0.2.1](https://github.com/roquerodrigo/ttlock-ble/compare/v0.2.0...v0.2.1) (2026-08-26)


### Features

* **client:** add admin-gated set_lock_sound command ([8b277c2](https://github.com/roquerodrigo/ttlock-ble/commit/8b277c268c38ad036b68099fa92f345fff5e8ee8))


### Miscellaneous Chores

* ignore .vscode directory ([a328666](https://github.com/roquerodrigo/ttlock-ble/commit/a328666548f7cab68275eef590baa4d5360fc123))

## [0.2.0](https://github.com/roquerodrigo/ttlock-ble/compare/v0.1.11...v0.2.0) (2026-08-25)


### ⚠ BREAKING CHANGES

* **advertisement:** LockAdvertisement.lock_state is now LockState | None. Consumers must treat None as "state unknown" rather than assume a bolt position.

### Features

* **packaging:** require Python 3.14 ([37a2bc8](https://github.com/roquerodrigo/ttlock-ble/commit/37a2bc833ef26f88d8df3d22a24c1170641fa58b))


### Bug Fixes

* **advertisement:** stop reporting a dormant lock as locked ([e49bf1c](https://github.com/roquerodrigo/ttlock-ble/commit/e49bf1c7b7ff7c09f5eb96387cd037a0abc4e3c2))
* **build:** restore the hatchling build backend identifier ([67ba654](https://github.com/roquerodrigo/ttlock-ble/commit/67ba654a7384243b17424192e9419df72932472f))


### Code Refactoring

* **ble:** move the BLE link out of TTLockClient into its own layer ([3e4d055](https://github.com/roquerodrigo/ttlock-ble/commit/3e4d055543e2f87fef21c336da6ef6989668f315))
* **commands:** decode operate-log tails through a dispatch table ([a5a1402](https://github.com/roquerodrigo/ttlock-ble/commit/a5a1402021cdd2f3edf42ee02fdea615fdd57ccb))


### Dependencies

* **deps:** bump the python-deps group across 1 directory with 6 updates ([228d237](https://github.com/roquerodrigo/ttlock-ble/commit/228d237a299f3f78af3f4d4476472b25085c5a6b))


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
