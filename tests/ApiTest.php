<?php

namespace Tests;

use PHPUnit\Framework\TestCase;

/**
 * API Tests for Paranoia Matrix Admin Panel
 * 
 * Tests Matrix API integration with mocked responses
 */
class ApiTest extends TestCase
{
    protected function setUp(): void
    {
        $_SESSION = [];
    }

    protected function tearDown(): void
    {
        $_SESSION = [];
    }

    /**
     * @group api
     * @group matrix
     */
    public function testMatrixRequestSuccessfulLogin(): void
    {
        $url = MATRIX_SERVER . '/_matrix/client/r0/login';
        $result = test_makeMatrixRequest($url, 'POST', json_encode([
            'type' => 'm.login.password',
            'user' => 'testuser',
            'password' => 'testpass'
        ]), ['Content-Type: application/json']);

        $this->assertTrue($result['success']);
        $this->assertEquals(200, $result['http_code']);
        
        $response = json_decode($result['response'], true);
        $this->assertArrayHasKey('access_token', $response);
        $this->assertEquals('test_token_123', $response['access_token']);
    }

    /**
     * @group api
     * @group matrix
     */
    public function testMatrixRequestAdminVerification(): void
    {
        $url = MATRIX_SERVER . '/_synapse/admin/v1/users/@testuser:' . MATRIX_DOMAIN . '/admin';
        $result = test_makeMatrixRequest($url, 'GET', null, [
            'Authorization: Bearer test_token_123'
        ]);

        $this->assertTrue($result['success']);
        $this->assertEquals(200, $result['http_code']);
        
        $response = json_decode($result['response'], true);
        $this->assertArrayHasKey('admin', $response);
        $this->assertTrue($response['admin']);
    }

    /**
     * @group api
     * @group matrix
     */
    public function testMatrixRequestGenericSuccess(): void
    {
        $url = MATRIX_SERVER . '/_synapse/admin/v2/users';
        $result = test_makeMatrixRequest($url);

        $this->assertTrue($result['success']);
        $this->assertEquals(200, $result['http_code']);
        
        $response = json_decode($result['response'], true);
        $this->assertArrayHasKey('success', $response);
        $this->assertTrue($response['success']);
    }

    /**
     * @group api
     * @group matrix
     */
    public function testMatrixRequestWithDifferentMethods(): void
    {
        $baseUrl = MATRIX_SERVER . '/_synapse/admin/v2/users/@testuser:' . MATRIX_DOMAIN;
        
        // Test GET
        $getResult = test_makeMatrixRequest($baseUrl, 'GET');
        $this->assertTrue($getResult['success']);
        $this->assertEquals(200, $getResult['http_code']);
        
        // Test PUT
        $putResult = test_makeMatrixRequest($baseUrl, 'PUT', json_encode(['admin' => true]));
        $this->assertTrue($putResult['success']);
        $this->assertEquals(200, $putResult['http_code']);
        
        // Test POST
        $postResult = test_makeMatrixRequest($baseUrl . '/password', 'POST', json_encode(['new_password' => 'newpass']));
        $this->assertTrue($postResult['success']);
        $this->assertEquals(200, $postResult['http_code']);
    }

    /**
     * @group api
     * @group matrix
     */
    public function testMatrixRequestWithHeaders(): void
    {
        $headers = [
            'Content-Type: application/json',
            'Authorization: Bearer test_token_123',
            'User-Agent: Paranoia/1.0'
        ];
        
        $result = test_makeMatrixRequest(MATRIX_SERVER . '/test', 'GET', null, $headers);
        
        $this->assertTrue($result['success']);
        $this->assertEquals(200, $result['http_code']);
    }

    /**
     * @group api
     * @group matrix
     */
    public function testMatrixRequestUrlPatterns(): void
    {
        // Test various URL patterns that should trigger different mock responses
        $testUrls = [
            MATRIX_SERVER . '/_matrix/client/r0/login' => 'access_token',
            MATRIX_SERVER . '/_synapse/admin/v1/users/@user:domain.com/admin' => 'admin',
            MATRIX_SERVER . '/_synapse/admin/v2/users' => 'success',
            MATRIX_SERVER . '/_synapse/admin/v1/users/@user:domain.com/password' => 'success',
            MATRIX_SERVER . '/some/other/endpoint' => 'success'
        ];
        
        foreach ($testUrls as $url => $expectedKey) {
            $result = test_makeMatrixRequest($url);
            $this->assertTrue($result['success'], "URL: $url should succeed");
            
            $response = json_decode($result['response'], true);
            $this->assertArrayHasKey($expectedKey, $response, "URL: $url should have key: $expectedKey");
        }
    }
} 