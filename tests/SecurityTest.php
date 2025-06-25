<?php

namespace Tests;

use PHPUnit\Framework\TestCase;

/**
 * Security Tests for Paranoia Matrix Admin Panel
 * 
 * Tests security-critical functions like validation, CSRF, rate limiting
 */
class SecurityTest extends TestCase
{
    protected function setUp(): void
    {
        // Reset session for each test
        $_SESSION = [];
    }

    protected function tearDown(): void
    {
        // Clean up after each test
        $_SESSION = [];
        if (file_exists(LOG_FILE)) {
            unlink(LOG_FILE);
        }
    }

    /**
     * @group security
     * @group validation
     */
    public function testValidateUsernameAcceptsValidUsernames(): void
    {
        $validUsernames = [
            'testuser',
            'test_user',
            'test-user',
            'test.user',
            'user123',
            'TEST_USER_123',
            'a',
            '123'
        ];

        foreach ($validUsernames as $username) {
            $this->assertTrue(
                test_validateUsername($username),
                "Username '{$username}' should be valid"
            );
        }
    }

    /**
     * @group security
     * @group validation
     */
    public function testValidateUsernameRejectsInvalidUsernames(): void
    {
        $invalidUsernames = [
            '',
            ' ',
            'test user',
            'test@user',
            'test#user',
            'test$user',
            'test%user',
            'test&user',
            'test*user',
            'test+user',
            'test=user',
            'test?user',
            'test!user',
            'test/user',
            'test\\user',
            'test|user',
            'test<user',
            'test>user',
            'test(user)',
            'test[user]',
            'test{user}',
            'тест', // Cyrillic
            '测试', // Chinese
        ];

        foreach ($invalidUsernames as $username) {
            $this->assertFalse(
                test_validateUsername($username),
                "Username '{$username}' should be invalid"
            );
        }
    }

    /**
     * @group security
     * @group csrf
     */
    public function testCsrfTokenVerificationWithValidToken(): void
    {
        $token = 'test_csrf_token_123';
        $_SESSION['csrf_token'] = $token;
        
        $this->assertTrue(test_verifyCsrf($token));
    }

    /**
     * @group security
     * @group csrf
     */
    public function testCsrfTokenVerificationWithInvalidToken(): void
    {
        $_SESSION['csrf_token'] = 'correct_token';
        
        $this->assertFalse(test_verifyCsrf('wrong_token'));
        $this->assertFalse(test_verifyCsrf(''));
        $this->assertFalse(test_verifyCsrf(null));
    }

    /**
     * @group security
     * @group csrf
     */
    public function testCsrfTokenVerificationWithoutSessionToken(): void
    {
        // No token in session
        unset($_SESSION['csrf_token']);
        
        $this->assertFalse(test_verifyCsrf('any_token'));
    }

    /**
     * @group security
     * @group rate-limiting
     */
    public function testRateLimitingInitialState(): void
    {
        // Initially should allow requests
        $this->assertTrue(test_checkRateLimit());
    }

    /**
     * @group security
     * @group rate-limiting
     */
    public function testRateLimitingAfterFailedAttempts(): void
    {
        // Increment failed attempts up to the limit
        for ($i = 0; $i < MAX_FAILED_ATTEMPTS; $i++) {
            $this->assertTrue(test_checkRateLimit(), "Should allow attempt $i");
            test_incrementFailedAttempts();
        }
        
        // Now should be rate limited
        $this->assertFalse(test_checkRateLimit(), 'Should be rate limited after max attempts');
    }

    /**
     * @group security
     * @group rate-limiting
     */
    public function testRateLimitingReset(): void
    {
        // Max out failed attempts
        $_SESSION['failed_attempts'] = MAX_FAILED_ATTEMPTS;
        $this->assertFalse(test_checkRateLimit());
        
        // Reset should allow requests again
        test_resetFailedAttempts();
        $this->assertTrue(test_checkRateLimit());
    }

    /**
     * @group security
     * @group authorization
     */
    public function testActionAllowedForDifferentUsers(): void
    {
        $_SESSION['admin_user'] = '@admin:test.com';
        
        // Should allow actions on other users
        $this->assertTrue(test_isActionAllowed('deactivate', '@other:test.com'));
        $this->assertTrue(test_isActionAllowed('remove_admin', '@other:test.com'));
        $this->assertTrue(test_isActionAllowed('any_action', '@other:test.com'));
    }

    /**
     * @group security
     * @group authorization
     */
    public function testActionNotAllowedForSelfDeactivation(): void
    {
        $_SESSION['admin_user'] = '@admin:test.com';
        
        // Should not allow self-deactivation
        $this->assertFalse(test_isActionAllowed('deactivate', '@admin:test.com'));
    }

    /**
     * @group security
     * @group authorization
     */
    public function testActionNotAllowedForSelfAdminRemoval(): void
    {
        $_SESSION['admin_user'] = '@admin:test.com';
        
        // Should not allow removing own admin privileges
        $this->assertFalse(test_isActionAllowed('remove_admin', '@admin:test.com'));
    }

    /**
     * @group security
     * @group authorization
     */
    public function testActionAllowedForOtherActions(): void
    {
        $_SESSION['admin_user'] = '@admin:test.com';
        
        // Should allow other actions on self
        $this->assertTrue(test_isActionAllowed('change_password', '@admin:test.com'));
        $this->assertTrue(test_isActionAllowed('view_profile', '@admin:test.com'));
        $this->assertTrue(test_isActionAllowed('unknown_action', '@admin:test.com'));
    }
} 