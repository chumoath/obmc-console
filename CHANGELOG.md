# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Change categories:

- Added
- Changed
- Deprecated
- Removed
- Fixed
- Security

## [Unreleased]

### Added

1. config: Added support for the `aspeed-uart-routing` configuration key
2. config: Added support for the `ringbuffer-size` configuration key
3. UART multiplexer support

   More details can be found [in the documentation](docs/mux-support.md).

4. Integration tests

   Note that it's now advised to run `meson test ...` under [dbus-run-session][]
   as the integration tests connect to the session bus.

[dbus-run-session]:
  https://manpages.debian.org/bookworm/dbus-daemon/dbus-run-session.1.en.html

### Changed:

1. The bespoke config parser was replaced with iniparser

### Removed

1. Deprecated D-Bus interface `xyz.openbmc_project.console` is no longer used.
2. config: Drop support for the `socket-id` configuration key

### Fixed

1. console-server: Fix configuration of lpc_address and sirq sysfs attributes
2. config.h: Include stddef.h for size_t
3. console-server: Fix pointer arithmetic in container_of() implementation

## [1.1.0] - 2023-06-07

### Added

1. console-server: Add PTY support for testing purposes
2. console-server: Add --console-id option
3. console-server: Add DBUS interface to find console unix socket FD.
4. Implement D-Bus interface `xyz.openbmc_project.Console.UART` for UART TTY
   devices.

### Changed

1. The `xyz.openbmc_project.console` interface is only published if the
   underlying TTY device is a UART and not a VUART nor PTY (where baud is not
   applicable)

2. console-server: Don't require a configuration file

   Passing the `--config` option is no longer required when invoking
   `obmc-console-server`.

### Deprecated

1. obmc-console: Introduce console-id, deprecate socket-id

   Deprecate the `socket-id` key in the configuration schema. Uses of
   `socket-id` should be directly replaced with `console-id`.

2. Deprecate the `xyz.openbmc_project.console` D-Bus interface in favor of the
   functionally equivalent `xyz.openbmc_project.Console.UART`.

### Fixed

1. obmc-console: Consolidate handling of default socket-id

### Fixed

1. log-handler: Set the end of the file as the file size
