# Changelog

All notable changes to this project will be documented in this file.

## [v2.0.0] - 2025-02-08
### Added
- New BlenderAnalyzer implementation with Moneta, HSB, and HollowsHunter integration
- Blender endpoint for system scanning and payload comparison
- New Dynamic Analyzer HollowsHunter

### Fixed
- Scanners output parsing improvements


## [v1.6.1] - 2025-01-27
### Added
- Captured and displayed payload output for better analysis.
- Enhanced the Stringnalyzer scanner with improved functionality.

### Changed
- Summary section now includes Stringnalyzer & Payload output results.
- Improved HTML and JavaScript code for analysis results. 
- Renamed the 'upload' section in the YAML config file to 'util'.

### Fixed
- Resolved missing IOC issue in Moneta.
- Multiple bug fixes in summary section

## [v1.6.0] - 2025-01-26
### Added
- New Static analyzer Stringnalyzer implementation

### Fixed
- Refactoring health check implementation to use configuration file settings


## [v1.5.1] - 2025-01-25
### Added
- Support for executing payloads with custom command-line arguments
- Increased default payload size limit to 100MB
- Configurable payload initialization timeout settings
- New Version for PE-Sieve scanner

### Fixed
- Improved error handling for payloads that terminate before scan completion
- Enhanced UI/UX for clearer error messaging and handling


## [v1.5.0] - 2025-01-11
### Added
- New Dynamic analyzer RedEdr Scanner implementation
- Added LICENSE file

### Changed
- Various code refactoring improvements

### Fixed
- Multiple bug fixes


## [v1.2.1] - 2025-01-06
### Added
- Debug mode enabled
- Small improvements to core functionality


## [v1.2.0] - 2025-01-05
### Added
- API route for results with JSON output (@som3canadian)
- Improved risk calculation system
- Enhanced summary section with better reporting

### Changed
- Documentation improvements
- Updated README with new features and instructions

### Fixed
- Code optimization and cleanup
- Risk calculation refinements


## [v1.0.0] - 2025-01-04
### Added
- Initial release
- Base functionality implementation
- Core scanning features

### Notes
- Repository initialized with basic documentation
