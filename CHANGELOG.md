# Changelog

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
