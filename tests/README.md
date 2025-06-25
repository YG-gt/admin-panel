# 🧪 Paranoia Testing Suite

Comprehensive PHPUnit testing for the Matrix admin panel.

## 🚀 Quick Start

```bash
# Install dependencies
composer install

# Run all tests
composer test

# Run with coverage
composer test-coverage
```

## 🎯 Test Categories

- **Security Tests** - Validation, CSRF, rate limiting
- **Logging Tests** - Audit trail functionality  
- **API Tests** - Matrix API integration (mocked)

## 🏃‍♂️ Running Tests

```bash
# Specific groups
./vendor/bin/phpunit --group=security
./vendor/bin/phpunit --group=logging
./vendor/bin/phpunit --group=api

# Individual test files
./vendor/bin/phpunit tests/SecurityTest.php
./vendor/bin/phpunit tests/LoggingTest.php
./vendor/bin/phpunit tests/ApiTest.php
```

## 🤖 GitHub Actions

Tests run automatically on push/PR for PHP 8.1, 8.2, 8.3 with security scanning.

## 🔒 Philosophy

Tests maintain the "zero dependencies" philosophy - they're optional dev tools that don't affect production deployment. 