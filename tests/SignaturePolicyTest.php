<?php

use Jumbojett\OpenIDConnectClient;
use Jumbojett\OpenIDConnectClientException;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\PrivateKey;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class SignaturePolicyTest extends TestCase
{
    private const JWKS_URI = 'https://issuer.example/jwks';

    /** @var PrivateKey|null */
    private static $signingKey;

    public function testDefaultAcceptsRs256()
    {
        $key = $this->rsaJwk(['alg' => 'RS256', 'use' => 'sig', 'key_ops' => ['verify']]);

        self::assertTrue($this->rsaClient([$key])->verifyJWTSignature($this->rsaJwt('RS256')));
    }

    public function testDefaultRejectsHmacDespiteProviderCapabilities()
    {
        $secret = str_repeat('s', 32);
        $client = new OpenIDConnectClient('https://issuer.example', 'client-id', $secret);
        $client->providerConfigParam(['id_token_signing_alg_values_supported' => ['RS256', 'HS256']]);

        $this->expectException(OpenIDConnectClientException::class);
        $client->verifyJWTSignature($this->hmacJwt('HS256', $secret));
    }

    public function testConstructorAllowsMultipleAlgorithms()
    {
        $client = $this->rsaClient(null, ['RS256', 'PS256']);

        self::assertTrue($client->verifyJWTSignature($this->rsaJwt('RS256')));
        self::assertTrue($client->verifyJWTSignature($this->rsaJwt('PS256')));
    }

    public function testSetterReplacesRatherThanExtendsPolicy()
    {
        $client = $this->rsaClient();
        $client->setExpectedAlgorithms(['PS256']);

        self::assertTrue($client->verifyJWTSignature($this->rsaJwt('PS256')));
        $this->expectException(OpenIDConnectClientException::class);
        $client->verifyJWTSignature($this->rsaJwt('RS256'));
    }

    /**
     * @dataProvider invalidAlgorithmLists
     */
    public function testRejectsInvalidAlgorithmLists(array $algorithms)
    {
        $this->expectException(OpenIDConnectClientException::class);
        new OpenIDConnectClient(null, null, null, null, $algorithms);
    }

    public function invalidAlgorithmLists(): array
    {
        return [
            'empty' => [[]],
            'unsupported' => [['none']],
        ];
    }

    public function testInvalidSetterPreservesPolicy()
    {
        $client = $this->rsaClient(null, ['PS256']);
        try {
            $client->setExpectedAlgorithms(['RS256', 'none']);
            self::fail('An invalid algorithm list was accepted');
        } catch (OpenIDConnectClientException $e) {
            self::assertTrue($client->verifyJWTSignature($this->rsaJwt('PS256')));
        }

        $this->expectException(OpenIDConnectClientException::class);
        $client->verifyJWTSignature($this->rsaJwt('RS256'));
    }

    /**
     * @dataProvider invalidHeaderAlgorithms
     */
    public function testInvalidAlgorithmIsRejectedBeforeFetchingKeys(array $header)
    {
        $client = $this->rsaClient();
        $client->expects(self::never())->method('fetchURL');
        $jwt = $this->jwtPayload($header) . '.' . $this->encode('signature');

        $this->expectException(OpenIDConnectClientException::class);
        $client->verifyJWTSignature($jwt);
    }

    public function invalidHeaderAlgorithms(): array
    {
        return [
            'missing' => [[]],
            'wrong type' => [['alg' => ['RS256']]],
            'not allowed' => [['alg' => 'PS256']],
        ];
    }

    public function testMalformedKidFailsClosed()
    {
        $client = $this->rsaClient();

        $this->expectException(OpenIDConnectClientException::class);
        $client->verifyJWTSignature($this->rsaJwt('RS256', ['kid' => ['test-key']]));
    }

    public function testExplicitHmacUsesProvidedSecret()
    {
        $secret = 'provider-secret';
        $client = new OpenIDConnectClient(null, null, $secret, null, ['HS256']);

        self::assertTrue($client->verifyJWTSignature($this->hmacJwt('HS256', $secret)));
    }

    /**
     * @dataProvider missingHmacSecrets
     */
    public function testExplicitHmacRejectsMissingSecret(?string $secret)
    {
        $client = new OpenIDConnectClient(null, null, $secret, null, ['HS256']);

        $this->expectException(OpenIDConnectClientException::class);
        $client->verifyJWTSignature($this->hmacJwt('HS256', ''));
    }

    public function missingHmacSecrets(): array
    {
        return [
            'missing' => [null],
            'empty' => [''],
        ];
    }

    /**
     * @dataProvider invalidSignatureAlgorithms
     */
    public function testInvalidSignatureReturnsFalse(string $algorithm)
    {
        if ($algorithm === 'HS256') {
            $secret = str_repeat('s', 32);
            $client = new OpenIDConnectClient(null, null, $secret, null, [$algorithm]);
            $jwt = $this->hmacJwt($algorithm, $secret);
        } else {
            $client = $this->rsaClient();
            $jwt = $this->rsaJwt($algorithm);
        }
        $parts = explode('.', $jwt);
        $parts[1] = $this->encode(json_encode(['sub' => 'tampered']));
        $jwt = implode('.', $parts);

        self::assertFalse($client->verifyJWTSignature($jwt));
        $this->expectException(OpenIDConnectClientException::class);
        $client->verifySignatures($jwt);
    }

    public function invalidSignatureAlgorithms(): array
    {
        return [
            'RSA' => ['RS256'],
            'HMAC' => ['HS256'],
        ];
    }

    /**
     * @dataProvider ineligibleJwks
     */
    public function testRejectsIneligibleJwk(array $restrictions)
    {
        $client = $this->rsaClient([$this->rsaJwk($restrictions)]);

        $this->expectException(OpenIDConnectClientException::class);
        $client->verifyJWTSignature($this->rsaJwt('RS256'));
    }

    public function ineligibleJwks(): array
    {
        return [
            'wrong key type' => [['kty' => 'oct', 'alg' => 'RS256']],
            'conflicting algorithm' => [['alg' => 'PS256']],
            'encryption key' => [['use' => 'enc']],
            'sign-only operations' => [['key_ops' => ['sign']]],
            'declared null algorithm' => [['alg' => null]],
            'malformed operations' => [['key_ops' => 'verify']],
        ];
    }

    public function testKeyLookupSkipsIneligibleKeysAndUsesAdditionalKeys()
    {
        $client = $this->additionalKeyClient([$this->unrelatedJwk(['use' => 'enc'])]);
        $client->addTestJwk($this->unrelatedJwk(['use' => 'enc']));
        $client->addTestJwk($this->rsaJwk());

        self::assertTrue($client->verifyJWTSignature($this->rsaJwt('RS256')));
    }

    public function testProviderKeysPrecedeAdditionalKeys()
    {
        $client = $this->additionalKeyClient([$this->rsaJwk()]);
        $client->addTestJwk($this->unrelatedJwk());

        self::assertTrue($client->verifyJWTSignature($this->rsaJwt('RS256')));
    }

    public function testEmbeddedJwkRequiresExplicitOptIn()
    {
        $client = new class extends OpenIDConnectClient {
            protected function verifyJWKHeader($jwk)
            {
            }
        };

        $this->expectException(OpenIDConnectClientException::class);
        $client->verifyJWTSignature($this->rsaJwt('RS256', ['jwk' => $this->rsaJwk()]));
    }

    public function testNullJwkHeaderIsDisabledByDefaultForHmac()
    {
        $secret = str_repeat('s', 32);
        $client = new OpenIDConnectClient(null, null, $secret, null, ['HS256']);

        $this->expectException(OpenIDConnectClientException::class);
        $client->verifyJWTSignature($this->hmacJwt('HS256', $secret, ['jwk' => null]));
    }

    public function testEmbeddedJwkCanBeEnabledAndDisabled()
    {
        $client = new OpenIDConnectClient();
        $client->setAllowJWKHeader(true);
        $jwt = $this->rsaJwt('RS256', ['jwk' => $this->rsaJwk()]);

        self::assertTrue($client->verifyJWTSignature($jwt));
        $client->setAllowJWKHeader(false);
        $this->expectException(OpenIDConnectClientException::class);
        $client->verifyJWTSignature($jwt);
    }

    public function testEmbeddedJwkStillEnforcesKeyMetadata()
    {
        $client = new OpenIDConnectClient();
        $client->setAllowJWKHeader(true);
        $jwt = $this->rsaJwt('RS256', ['jwk' => $this->rsaJwk(['use' => 'enc'])]);

        $this->expectException(OpenIDConnectClientException::class);
        $client->verifyJWTSignature($jwt);
    }

    public function testNullEmbeddedJwkDoesNotFetchProviderKeys()
    {
        $client = $this->rsaClient();
        $client->setAllowJWKHeader(true);
        $client->expects(self::never())->method('fetchURL');

        $this->expectException(OpenIDConnectClientException::class);
        $client->verifyJWTSignature($this->rsaJwt('RS256', ['jwk' => null]));
    }

    public function testEmbeddedJwkCallsOptionalSubclassValidator()
    {
        $client = new class extends OpenIDConnectClient {
            protected function verifyJWKHeader($jwk)
            {
                throw new OpenIDConnectClientException('Application rejected embedded JWK');
            }
        };
        $client->setAllowJWKHeader(true);

        $this->expectException(OpenIDConnectClientException::class);
        $this->expectExceptionMessage('Application rejected embedded JWK');
        $client->verifyJWTSignature($this->rsaJwt('RS256', ['jwk' => $this->rsaJwk()]));
    }

    public function testRemoteKeyHeadersAreIgnored()
    {
        $client = $this->rsaClient();
        $jwt = $this->rsaJwt('RS256', [
            'jku' => 'https://untrusted.example/keys',
            'x5u' => 'https://untrusted.example/certificate',
        ]);

        self::assertTrue($client->verifyJWTSignature($jwt));
    }

    /**
     * @dataProvider malformedJwks
     */
    public function testMalformedJwksFailsWithLibraryException(string $response)
    {
        $client = $this->jwksClient($response);

        $this->expectException(OpenIDConnectClientException::class);
        $client->verifyJWTSignature($this->rsaJwt('RS256'));
    }

    public function malformedJwks(): array
    {
        return [
            'invalid JSON' => ['not JSON'],
            'non-array keys' => ['{"keys":"invalid"}'],
        ];
    }

    private function rsaClient(?array $keys = null, ?array $expectedAlgorithms = null): OpenIDConnectClient
    {
        return $this->jwksClient(json_encode(['keys' => $keys ?? [$this->rsaJwk()]]), $expectedAlgorithms);
    }

    private function jwksClient(string $response, ?array $expectedAlgorithms = null): OpenIDConnectClient
    {
        $arguments = ['https://issuer.example', 'client-id', null, null];
        if ($expectedAlgorithms !== null) {
            $arguments[] = $expectedAlgorithms;
        }
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setConstructorArgs($arguments)
            ->setMethods(['fetchURL'])
            ->getMock();
        $client->providerConfigParam(['jwks_uri' => self::JWKS_URI]);
        $client->method('fetchURL')->with(self::JWKS_URI)->willReturn($response);
        return $client;
    }

    private function additionalKeyClient(array $providerKeys): OpenIDConnectClient
    {
        $client = new class extends OpenIDConnectClient {
            public $providerKeys;

            public function addTestJwk(stdClass $key)
            {
                $this->addAdditionalJwk($key);
            }

            protected function fetchURL(string $url, ?string $post_body = null, array $headers = [])
            {
                return json_encode(['keys' => $this->providerKeys]);
            }
        };
        $client->providerKeys = $providerKeys;
        $client->providerConfigParam(['jwks_uri' => self::JWKS_URI]);
        return $client;
    }

    private function unrelatedJwk(array $overrides = []): stdClass
    {
        $jwks = json_decode(file_get_contents(__DIR__ . '/data/jwks-ps256.json'));
        return (object)array_merge((array)$jwks->keys[0], ['kid' => 'test-key'], $overrides);
    }

    private function hmacJwt(string $algorithm, string $secret, array $header = []): string
    {
        $payload = $this->jwtPayload(array_merge(['alg' => $algorithm], $header));
        return $payload . '.' . $this->encode(hash_hmac('sha' . substr($algorithm, 2), $payload, $secret, true));
    }

    private function rsaJwt(string $algorithm, array $header = []): string
    {
        $payload = $this->jwtPayload(array_merge(['alg' => $algorithm, 'kid' => 'test-key'], $header));
        $hash = 'sha' . substr($algorithm, 2);
        $key = $this->signingKey()->withHash($hash);
        $key = strpos($algorithm, 'PS') === 0
            ? $key->withMGFHash($hash)->withPadding(RSA::SIGNATURE_PSS)
            : $key->withPadding(RSA::SIGNATURE_PKCS1);
        return $payload . '.' . $this->encode($key->sign($payload));
    }

    private function rsaJwk(array $overrides = []): stdClass
    {
        $jwks = json_decode($this->signingKey()->getPublicKey()->toString('JWK'));
        return (object)array_merge((array)$jwks->keys[0], ['kid' => 'test-key'], $overrides);
    }

    private function signingKey(): PrivateKey
    {
        if (self::$signingKey === null) {
            self::$signingKey = RSA::createKey(2048);
        }
        return self::$signingKey;
    }

    private function jwtPayload(array $header): string
    {
        return $this->encode(json_encode((object)$header)) . '.' . $this->encode(json_encode(['sub' => 'user']));
    }

    private function encode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
