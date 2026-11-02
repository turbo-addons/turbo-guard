<?php
/**
 * Base64-encoded CJK payload detection tests — SEO Spam Detector.
 *
 * Japanese/Chinese SEO-spam doorways hide their payload as a base64 blob (often
 * gzip-compressed) so the spam text is invisible to plain-text CJK scanning.
 * These tests lock the generic (non-static) detection: the detector must flag
 * any base64/gzip blob that decodes to CJK, regardless of the doorway URL
 * prefix, variable names, or whether a rewrite rule is registered.
 *
 * @package TurboGuard\Tests\Unit\SeoSpamDetector
 */

declare(strict_types=1);

namespace TurboGuard\Tests\Unit\SeoSpamDetector;

use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use Turbo_Guard_SEO_Spam_Detector;

/**
 * Tests for has_base64_encoded_cjk() and its integration into
 * looks_like_doorway_generator().
 */
class Base64CjkTest extends TestCase {

	// Base64 of Japanese spam text: 'スーパーコピー ブランド品 激安 偽物 送料無料 最安値'.
	private const B64_JAPANESE = '44K544O844OR44O844Kz44OU44O8IOODluODqeODs+ODieWTgSDmv4Dlrokg5YG954mpIOmAgeaWmeeEoeaWmSDmnIDlronlgKQ=';

	// gzip-deflated then base64 of Japanese spam text: 'スーパーコピー ブランド品 激安 偽物'.
	private const B64_JAPANESE_GZIP = 'e9y083HznsfNE0Fk0+bHzVOADIXHzdMeN6983Azkdz6d3KjwbH/D03WdCk8b9z7vXAkA';

	// Base64 of plain ASCII text (must NOT be flagged).
	private const B64_ASCII = 'SGVsbG8gV29ybGQsIHRoaXMgaXMgYSBub3JtYWwgRW5nbGlzaCBzZW50ZW5jZSB3aXRoIG5vIENKSyBhdCBhbGwgMTIzNDU2Nzg5MA==';

	/**
	 * A base64 blob that decodes to Japanese must be detected.
	 */
	public function test_base64_encoded_japanese_is_detected(): void {
		$php = "<?php\n\$payload = base64_decode('" . self::B64_JAPANESE . "');\necho \$payload;\n";

		$this->assertTrue(
			self::invoke_has_base64_encoded_cjk( $php ),
			'A file containing base64-encoded Japanese spam must be detected by has_base64_encoded_cjk().'
		);
	}

	/**
	 * A gzip-compressed then base64 blob that decodes to Japanese must be detected.
	 */
	public function test_gzip_base64_encoded_japanese_is_detected(): void {
		$php = "<?php\necho gzinflate(base64_decode('" . self::B64_JAPANESE_GZIP . "'));\n";

		$this->assertTrue(
			self::invoke_has_base64_encoded_cjk( $php ),
			'A file containing gzip+base64-encoded Japanese spam must be detected by has_base64_encoded_cjk().'
		);
	}

	/**
	 * A base64 blob that decodes to plain ASCII must NOT be flagged.
	 */
	public function test_base64_ascii_is_not_detected(): void {
		$php = "<?php\n\$data = '" . self::B64_ASCII . "';\n\$text = base64_decode(\$data);\n";

		$this->assertFalse(
			self::invoke_has_base64_encoded_cjk( $php ),
			'A base64 blob that decodes to ASCII (not CJK) must not be flagged.'
		);
	}

	/**
	 * A file with no base64 content must NOT be flagged.
	 */
	public function test_no_base64_is_not_detected(): void {
		$php = "<?php\nfunction hello() {\n    return 'Hello World';\n}\n";

		$this->assertFalse(
			self::invoke_has_base64_encoded_cjk( $php ),
			'A file with no base64 string literals must not be flagged.'
		);
	}

	/**
	 * Integration: a realistic cloaked doorway backdoor — bot user-agent check,
	 * numeric-ID request match, base64-encoded Japanese payload, no rewrite rule
	 * and no CJK variable names — must be detected by looks_like_doorway_generator().
	 *
	 * This is the exact gap the fix closes: /products/128422362-style doorways
	 * whose prefix varies between campaigns.
	 */
	public function test_cloaked_numeric_doorway_with_base64_japanese_is_detected(): void {
		$php = <<<'PHP'
<?php
add_action('template_redirect', function () {
    $ua  = $_SERVER['HTTP_USER_AGENT'];
    $uri = $_SERVER['REQUEST_URI'];
    if (false !== strpos($ua, 'Googlebot') && preg_match('#^/products/(\d+)/?$#', $uri)) {
        echo base64_decode('44K544O844OR44O844Kz44OU44O8IOODluODqeODs+ODieWTgSDmv4Dlrokg5YG954mpIOmAgeaWmeeEoeaWmSDmnIDlronlgKQ=');
        exit;
    }
});
PHP;

		$this->assertTrue(
			self::invoke_looks_like_doorway_generator( $php ),
			'A cloaked doorway backdoor (bot UA + numeric route + base64 Japanese, ' .
			'no rewrite rule, no CJK vars) must be detected as a doorway generator.'
		);
	}

	// ──────────────────────────────────────────────────────────────────────────
	// Helpers
	// ──────────────────────────────────────────────────────────────────────────

	private static function invoke_has_base64_encoded_cjk( string $content ): bool {
		$method = new ReflectionMethod( Turbo_Guard_SEO_Spam_Detector::class, 'has_base64_encoded_cjk' );
		$method->setAccessible( true );
		return (bool) $method->invoke( null, $content );
	}

	private static function invoke_looks_like_doorway_generator( string $content ): bool {
		$method = new ReflectionMethod( Turbo_Guard_SEO_Spam_Detector::class, 'looks_like_doorway_generator' );
		$method->setAccessible( true );
		return (bool) $method->invoke( null, $content );
	}
}
