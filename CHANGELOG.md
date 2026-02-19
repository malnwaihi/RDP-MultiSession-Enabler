# Changelog

## [6.4] - 2026-02-19

### Added
- Support for Windows 11 25H2 (Builds 26120-26299)
- Better error messages for common issues
- Session monitoring with `Get-RDPSessions` function

### Fixed
- Syntax errors in persistence script
- Missing closing braces in various functions
- Unicode character issues in console output
- Null comparison warnings from PSScriptAnalyzer

### Changed
- Replaced Unicode box drawing with ASCII characters for better compatibility
- Improved error handling in patch application
- Better logging for troubleshooting

## [6.0] - 2026-02-15

### Added
- Persistence mechanisms to survive reboots
- Multiple backup locations for redundancy
- Scheduled task for auto-recovery
- Registry Run key for startup
- Windows Defender exclusions
- Windows File Protection bypass

### Changed
- Complete rewrite of core functions
- Better visualization with tables and progress bars

## [5.0] - 2026-02-10

### Added
- Byte-level validation for patches
- SHA256 hash verification for backups
- System Restore Point integration
- Support for Windows 11 24H2

### Fixed
- Permission issues when writing to system32
- Service stop/start timeout handling

## [4.0] - 2026-02-01

### Added
- Interactive menu system
- Color-coded output
- Session monitoring
- Windows 11 23H2 support

### Changed
- Improved OS detection
- Better error messages
