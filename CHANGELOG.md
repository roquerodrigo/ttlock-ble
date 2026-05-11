# Changelog

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
