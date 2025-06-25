<?php

namespace Tests;

use PHPUnit\Framework\TestCase;

/**
 * Logging Tests for Paranoia Matrix Admin Panel
 * 
 * Tests audit logging functionality
 */
class LoggingTest extends TestCase
{
    protected function setUp(): void
    {
        $_SESSION = [];
        // Clean log file before each test
        if (file_exists(LOG_FILE)) {
            unlink(LOG_FILE);
        }
    }

    protected function tearDown(): void
    {
        $_SESSION = [];
        if (file_exists(LOG_FILE)) {
            unlink(LOG_FILE);
        }
    }

    /**
     * @group logging
     */
    public function testLogActionCreatesLogFile(): void
    {
        $this->assertFileDoesNotExist(LOG_FILE);
        
        test_logAction('test action');
        
        $this->assertFileExists(LOG_FILE);
    }

    /**
     * @group logging
     */
    public function testLogActionWritesCorrectFormat(): void
    {
        $_SESSION['admin_user'] = '@testuser:test.com';
        
        test_logAction('login successful');
        
        $logContent = file_get_contents(LOG_FILE);
        
        // Should contain timestamp, user, and action
        $this->assertStringContainsString('@testuser:test.com', $logContent);
        $this->assertStringContainsString('login successful', $logContent);
        $this->assertStringContainsString('→', $logContent);
        
        // Should match the expected format: [timestamp] user → action
        $this->assertMatchesRegularExpression(
            '/^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] @testuser:test\.com → login successful\n$/',
            $logContent
        );
    }

    /**
     * @group logging
     */
    public function testLogActionWithUnknownUser(): void
    {
        // No user in session
        unset($_SESSION['admin_user']);
        
        test_logAction('anonymous action');
        
        $logContent = file_get_contents(LOG_FILE);
        $this->assertStringContainsString('unknown → anonymous action', $logContent);
    }

    /**
     * @group logging
     */
    public function testMultipleLogEntries(): void
    {
        $_SESSION['admin_user'] = '@admin:test.com';
        
        test_logAction('first action');
        test_logAction('second action');
        test_logAction('third action');
        
        $logContent = file_get_contents(LOG_FILE);
        $lines = explode("\n", trim($logContent));
        
        $this->assertCount(3, $lines);
        $this->assertStringContainsString('first action', $lines[0]);
        $this->assertStringContainsString('second action', $lines[1]);
        $this->assertStringContainsString('third action', $lines[2]);
    }

    /**
     * @group logging
     */
    public function testLogActionReturnsBytes(): void
    {
        $bytesWritten = test_logAction('test message');
        
        $this->assertIsInt($bytesWritten);
        $this->assertGreaterThan(0, $bytesWritten);
    }

    /**
     * @group logging
     */
    public function testLogActionWithSpecialCharacters(): void
    {
        $_SESSION['admin_user'] = '@test:domain.com';
        
        $specialActions = [
            'login failed: invalid credentials for "user@domain.com"',
            'create user @newuser:domain.com (admin)',
            'password changed for user with special chars: áéíóú',
            'action with quotes "test" and apostrophes \'test\'',
        ];
        
        foreach ($specialActions as $action) {
            test_logAction($action);
        }
        
        $logContent = file_get_contents(LOG_FILE);
        
        foreach ($specialActions as $action) {
            $this->assertStringContainsString($action, $logContent);
        }
    }

    /**
     * @group logging
     */
    public function testLogActionConcurrency(): void
    {
        $_SESSION['admin_user'] = '@concurrent:test.com';
        
        // Simulate concurrent writes
        $actions = [];
        for ($i = 0; $i < 10; $i++) {
            $action = "concurrent action $i";
            $actions[] = $action;
            test_logAction($action);
        }
        
        $logContent = file_get_contents(LOG_FILE);
        $lines = explode("\n", trim($logContent));
        
        $this->assertCount(10, $lines);
        
        // Verify all actions were logged
        foreach ($actions as $action) {
            $this->assertStringContainsString($action, $logContent);
        }
    }
} 