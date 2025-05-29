# Changelog

All notable changes to this project will be documented in this file.


## [v3.2.0] - 2025-05-29
### Changed
- Major code refactoring for improved efficiency and maintainability
- Eliminated code duplication across routes, utilities, analysis manager, and Python client
- Centralized common functionality with helper classes (RouteHelpers, FileTypeDetector, SecurityAnalyzer, RiskCalculator)
- Enhanced error handling with consistent patterns and unified validation methods
- Restructured AnalysisManager with focused methods and specialized validation
- Refactored Python client removing duplicate implementations and adding helper methods

### Fixed
- Report generation bug for PID-based analysis missing process_output attribute



## [v3.1.0] - 2025-05-22
### Added
- Implemented API endpoints for HTML report generation and retrieval
- Added report generation functionality to Utils class
- Introduced comprehensive HTML report template system
- Extended Python client library with report management capabilities


## [v3.0.1] - 2025-05-16
### Added
- Implemented PE file suspicious import classification using MalApi.io database
- Developed comprehensive analyzer implementation documentation

### Changed
- Enhanced README structure and content
- Improved suspicious import visualization in file upload interface
- Restructured directory organization for better maintainability


## [v3.0.0] - 2025-05-16
### Added
- Python Clients to interact with LitterBox Server 
  	* `grumpycat.py` - Standalone command-line client for direct server interaction
  	* `LitterBoxMCP.py` - MCP server interface for LitterBox Server communication


## [v2.5.2] - 2025-05-09
### Fixed
- Clinet Side: removed hard-coded size limit  
- Removed file-type detection based on extension

### Added
- File-type detection based on magic bytes


## [v2.5.1] - 2025-04-24
### Fixed
- Cleanup method bug fixed FuzzyDB delete
- README Update
- Bug Fixed: size limit

### Changed
- Yara Analyzer support YARA Forge format

### Added
- YARA Forge Extended set


## [v2.5.0] - 2025-02-16
### Added
- New FuzzyHash analyzer (ssdeep)
- FuzzyHash database with open-source tools
- Doppelganger endpoint providing a unified interface for both Blender and FuzzyHash
- New configuration section for Doppelganger
- Application version

### Fixed
- Relocated all Blender code to the Doppelganger section
- Enhanced cleanup method
- Improved folder structure and creation process
- Enhanced error handelig on Blender analyzer client side
- base.html template disaply app version


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
