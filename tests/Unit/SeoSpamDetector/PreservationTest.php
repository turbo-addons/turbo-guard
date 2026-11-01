<?php
/**
 * Preservation Tests — SEO Spam Detector
 *
 * These tests are written BEFORE the fix is applied and are EXPECTED TO PASS
 * on unfixed code. They lock the baseline: all existing correct detection
 * signals must remain unchanged after the fix is applied.
 *
 * Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 4.9, 4.10
 *
 * @package TurboGuard\Tests\Unit\SeoSpamDetector
 */

declare(strict_types=1);

namespace TurboGuard\Tests\Unit\SeoSpamDetector;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionMethod;
use ReflectionException;
use Turbo_Guard_SEO_Spam_Detector;

/**
 * Preservation property tests for Turbo_Guard_SEO_Spam_Detector.
 *
 * These tests confirm that inputs where NEITHER bug condition holds produce
 * identical output before and after the fix:
 *
 *   FOR ALL X WHERE NOT isBugCondition_FalsePositive(X)
 *                AND NOT isBugCondition_MissedSpam(X)
 *   DO ASSERT scan_original(X) = scan_fixed(X)
 *
 * All 10 tests must PASS on unfixed code — they record the correct baseline.
 */
class PreservationTest extends TestCase {

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1 — Latin brand keyword detection
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * has_spam_keyword('buy gucci bags online') must return 'gucci'.
     *
     * This covers the Latin BRAND_KEYWORDS path which is not part of either
     * bug condition.  It must work identically on unfixed and fixed code.
     *
     * Validates: Requirement 4.2
     */
    public function test_latin_brand_keyword_gucci_is_detected(): void {
        $result = self::invoke_has_spam_keyword( 'buy gucci bags online' );

        $this->assertSame(
            'gucci',
            $result,
            'has_spam_keyword("buy gucci bags online") must return "gucci". ' .
            'Actual: ' . var_export( $result, true )
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2 — Latin pharma keyword detection
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * has_spam_keyword('order viagra online') must return 'viagra'.
     *
     * This covers the Latin PHARMA_KEYWORDS path.
     *
     * Validates: Requirement 4.2
     */
    public function test_latin_pharma_keyword_viagra_is_detected(): void {
        $result = self::invoke_has_spam_keyword( 'order viagra online' );

        $this->assertSame(
            'viagra',
            $result,
            'has_spam_keyword("order viagra online") must return "viagra". ' .
            'Actual: ' . var_export( $result, true )
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3 — CJK variable name → immediate true in looks_like_doorway_generator
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * looks_like_doorway_generator() with PHP content containing CJK variable names
     * must return true immediately.
     *
     * The existing regex is: /\$[\x{4E00}-\x{9FFF}\x{3400}-\x{4DBF}\x{3040}-\x{30FF}]{2,}/u
     * It requires 2+ CONSECUTIVE CJK characters after the $ sigil.
     *
     * $注入代码 = "injected code" (4 consecutive CJK chars) → matches.
     * NOTE: $假PNG头 from the design doc example does NOT match because 假 and 头
     * are separated by ASCII "PNG" — the existing regex requires consecutive CJK.
     * We use $注入代码 which definitively triggers the existing early-return.
     *
     * This is the "check 1" early-return path in looks_like_doorway_generator()
     * and must not be touched by the fix.
     *
     * Validates: Requirement 4.3
     */
    public function test_cjk_variable_name_triggers_doorway_generator_true(): void {
        $php_content = <<<'PHP'
<?php
// Obfuscated backdoor using CJK variable names (consecutive CJK chars after $)
$注入代码 = base64_decode('SGVsbG8gV29ybGQ=');
echo $注入代码;
PHP;

        $result = self::invoke_looks_like_doorway_generator( $php_content );

        $this->assertTrue(
            $result,
            'looks_like_doorway_generator() must return true when the content contains ' .
            'a CJK variable name ($假PNG头). This is an existing signal that must not change. ' .
            'Actual: ' . var_export( $result, true )
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 4 — Numeric-ID route hook + obfuscation → true
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * looks_like_doorway_generator() with PHP containing add_rewrite_rule,
     * [0-9]+, and base64_decode must return true.
     *
     * This covers the "check 2" route-hook + obfuscation path.
     *
     * Validates: Requirement 4.3
     */
    public function test_numeric_id_route_hook_with_obfuscation_triggers_doorway_generator_true(): void {
        $php_content = <<<'PHP'
<?php
add_action('init', function() {
    add_rewrite_rule('^prize/([0-9]+)/?$', 'index.php?prize_id=$matches[1]', 'top');
});
add_filter('query_vars', function($vars) {
    $vars[] = 'prize_id';
    return $vars;
});
add_action('template_redirect', function() {
    $id = get_query_var('prize_id');
    if ($id) {
        echo base64_decode('PHNwYW0+Q29udGVudDwvc3BhbT4=');
    }
});
PHP;

        $result = self::invoke_looks_like_doorway_generator( $php_content );

        $this->assertTrue(
            $result,
            'looks_like_doorway_generator() must return true for PHP with add_rewrite_rule, ' .
            '[0-9]+, and base64_decode. This existing route-hook + obfuscation signal must not change. ' .
            'Actual: ' . var_export( $result, true )
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 5 — 2 CJK keywords, no route hook, no CJK variables → false
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * looks_like_doorway_generator() with only 2 keyword matches and no other
     * signals must return false.
     *
     * Two CJK keywords (below the ≥3 threshold) must NOT trigger a false
     * positive on a legitimate plugin file with translation strings.
     * Both unfixed and fixed code must agree here.
     *
     * Validates: Requirement 3.4
     */
    public function test_two_cjk_keywords_no_route_hook_returns_false(): void {
        // Only 2 CJK keywords — below any threshold that might be added.
        // No add_rewrite_rule, no CJK $variable names.
        $php_content = <<<'PHP'
<?php
/**
 * Legitimate multilingual helper with a couple of Japanese translation strings.
 */
function get_greeting(): string {
    return "ブランド";  // keyword 1
}
function get_label(): string {
    return "激安";      // keyword 2
}
// Normal PHP code below — no route hooks, no obfuscation
function calculate_price( float $price ): float {
    return $price * 1.1;
}
PHP;

        $result = self::invoke_looks_like_doorway_generator( $php_content );

        $this->assertFalse(
            $result,
            'looks_like_doorway_generator() must return false for PHP with only 2 CJK keywords ' .
            'and no route hook or CJK variable names. ' .
            'This confirms the ≥3 threshold prevents false positives on legitimate plugins. ' .
            'Actual: ' . var_export( $result, true )
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 6 — CJK run counting
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * count_distinct_cjk_runs() (or its inline equivalent) returns correct counts.
     *
     * NOTE: count_distinct_cjk_runs does NOT yet exist in unfixed code.
     * We access it via ReflectionMethod but catch ReflectionException and fall
     * back to the same inline logic (preg_match_all with CJK_RUN_REGEX).
     *
     * - 'ありがとう' → 1 distinct run (single word of 5 CJK chars)
     * - 'hello world' → 0 distinct runs (ASCII only)
     * - five-separate-runs string → 5 distinct runs
     *
     * Validates: Requirement 1.1 (count_distinct_cjk_runs is defined correctly)
     */
    public function test_count_distinct_cjk_runs_returns_correct_counts(): void {
        // Single run: ありがとう = 5 consecutive CJK chars = 1 run.
        $count_one = self::count_cjk_runs( 'ありがとう' );
        $this->assertSame(
            1,
            $count_one,
            'count_distinct_cjk_runs("ありがとう") must return 1. ' .
            'Actual: ' . $count_one
        );

        // ASCII-only text: 0 runs.
        $count_zero = self::count_cjk_runs( 'hello world' );
        $this->assertSame(
            0,
            $count_zero,
            'count_distinct_cjk_runs("hello world") must return 0. ' .
            'Actual: ' . $count_zero
        );

        // Five separate CJK runs separated by ASCII spaces.
        // Each segment is 4+ consecutive CJK chars → counts as one run.
        $five_runs = 'ありがとう hello グッチバッグ world ルイヴィトン foo バーバリー bar モンクレール';
        $count_five = self::count_cjk_runs( $five_runs );
        $this->assertSame(
            5,
            $count_five,
            'count_distinct_cjk_runs() must return 5 for a string with five separate CJK runs. ' .
            'String: "' . $five_runs . '". Actual: ' . $count_five
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 7 (Property-based) — All BRAND_KEYWORDS still flagged
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * For each entry in BRAND_KEYWORDS, has_spam_keyword() must return that keyword.
     *
     * This is a property-based test using PHPUnit data providers to exhaustively
     * cover every brand keyword in the constant.
     *
     * Validates: Requirement 4.2
     *
     * @dataProvider brandKeywordsProvider
     */
    public function test_all_brand_keywords_are_detected( string $keyword ): void {
        // Embed the keyword in a sentence to reflect real-world usage.
        $text   = 'buy ' . $keyword . ' bags for cheap online';
        $result = self::invoke_has_spam_keyword( $text );

        $this->assertSame(
            $keyword,
            $result,
            sprintf(
                'has_spam_keyword() must return "%s" when the text contains that BRAND_KEYWORDS entry. ' .
                'Text: "%s". Actual: %s',
                $keyword,
                $text,
                var_export( $result, true )
            )
        );
    }

    /**
     * Data provider: all BRAND_KEYWORDS entries.
     *
     * @return array<string, array{0: string}>
     */
    public static function brandKeywordsProvider(): array {
        $keywords = self::get_class_constant( 'BRAND_KEYWORDS' );
        $cases    = array();
        foreach ( $keywords as $kw ) {
            $cases[ $kw ] = array( $kw );
        }
        return $cases;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 8 (Property-based) — All PHARMA_KEYWORDS still flagged
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * For each entry in PHARMA_KEYWORDS, has_spam_keyword() must return that keyword.
     *
     * Validates: Requirement 4.2
     *
     * @dataProvider pharmaKeywordsProvider
     */
    public function test_all_pharma_keywords_are_detected( string $keyword ): void {
        $text   = 'order ' . $keyword . ' without prescription';
        $result = self::invoke_has_spam_keyword( $text );

        $this->assertSame(
            $keyword,
            $result,
            sprintf(
                'has_spam_keyword() must return "%s" when the text contains that PHARMA_KEYWORDS entry. ' .
                'Text: "%s". Actual: %s',
                $keyword,
                $text,
                var_export( $result, true )
            )
        );
    }

    /**
     * Data provider: all PHARMA_KEYWORDS entries.
     *
     * @return array<string, array{0: string}>
     */
    public static function pharmaKeywordsProvider(): array {
        $keywords = self::get_class_constant( 'PHARMA_KEYWORDS' );
        $cases    = array();
        foreach ( $keywords as $kw ) {
            $cases[ $kw ] = array( $kw );
        }
        return $cases;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 9 (Property-based) — ASCII-only text with no keywords → false
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * has_spam_keyword() returns false for plain ASCII text containing no spam keywords.
     *
     * On unfixed code this must pass — normal text should not be flagged.
     * On fixed code this must also pass — the CJK dictionary only matches CJK.
     *
     * Validates: Requirement 4.2 (Latin paths), 1.2 (false positive prevention)
     */
    public function test_ascii_only_text_with_no_keywords_returns_false(): void {
        $benign_texts = array(
            'hello world this is a normal sentence',
            'welcome to our store — great deals every day',
            'contact us at support@example.com for help',
            'we sell quality shoes, bags, and accessories',
            'buy two get one free on all items this week',
        );

        foreach ( $benign_texts as $text ) {
            $result = self::invoke_has_spam_keyword( $text );
            $this->assertFalse(
                $result,
                sprintf(
                    'has_spam_keyword() must return false for ASCII-only text with no spam keywords. ' .
                    'Text: "%s". Actual: %s',
                    $text,
                    var_export( $result, true )
                )
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 10 (Property-based) — <5 CJK runs, no keyword → false
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * has_spam_keyword('ありがとう') — 1 CJK run, 0 spam keywords — returns false.
     *
     * On unfixed code this must pass: has_spam_keyword() only checks Latin
     * keywords, so a Japanese word with no Latin or CJK spam keyword returns
     * false (the false positive in the OLD code comes from a separate bare
     * preg_match path in scan_posts, not from has_spam_keyword itself).
     *
     * On fixed code this must also pass: 'ありがとう' is not in CJK_SPAM_KEYWORDS.
     *
     * This test specifically verifies that has_spam_keyword() does not
     * over-fire on benign CJK text with < 5 runs.
     *
     * Validates: Requirement 1.2
     */
    public function test_single_cjk_run_with_no_spam_keyword_returns_false(): void {
        $benign_cjk_texts = array(
            'ありがとう',           // 1 run: Japanese "thank you"
            'こんにちは',           // 1 run: Japanese "hello"
            'こんにちは ありがとう', // 2 runs: still below threshold, no keyword
            '漢字 テスト',          // 2 runs: kanji + katakana, no keyword
        );

        foreach ( $benign_cjk_texts as $text ) {
            $result = self::invoke_has_spam_keyword( $text );
            $this->assertFalse(
                $result,
                sprintf(
                    'has_spam_keyword() must return false for CJK text with no spam keywords. ' .
                    'Text: "%s". Actual: %s',
                    $text,
                    var_export( $result, true )
                )
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Get a class constant from Turbo_Guard_SEO_Spam_Detector via Reflection.
     * Returns the constant value, or null if the constant doesn't exist.
     */
    private static function get_class_constant( string $name ): mixed {
        $ref = new ReflectionClass( Turbo_Guard_SEO_Spam_Detector::class );
        $value = $ref->getConstant( $name );
        return ( false === $value ) ? null : $value;
    }

    /**
     * Invoke the private static has_spam_keyword() method.
     *
     * @return string|false  Matched keyword string, or false if none found.
     */
    private static function invoke_has_spam_keyword( string $text ): string|false {
        $method = new ReflectionMethod( Turbo_Guard_SEO_Spam_Detector::class, 'has_spam_keyword' );
        $method->setAccessible( true );
        return $method->invoke( null, $text );
    }

    /**
     * Invoke the private static looks_like_doorway_generator() method.
     */
    private static function invoke_looks_like_doorway_generator( string $content ): bool {
        $method = new ReflectionMethod( Turbo_Guard_SEO_Spam_Detector::class, 'looks_like_doorway_generator' );
        $method->setAccessible( true );
        return (bool) $method->invoke( null, $content );
    }

    /**
     * Count distinct CJK runs in a string.
     *
     * Tries to call the class method count_distinct_cjk_runs() via Reflection
     * (available only after the fix is applied). If the method does not exist
     * yet (ReflectionException), falls back to inline preg_match_all with
     * CJK_RUN_REGEX — identical logic to what the method will contain.
     *
     * This means Test 6 passes on BOTH unfixed code (method absent → inline
     * fallback) and fixed code (method present → reflection call).
     */
    private static function count_cjk_runs( string $text ): int {
        try {
            $method = new ReflectionMethod( Turbo_Guard_SEO_Spam_Detector::class, 'count_distinct_cjk_runs' );
            $method->setAccessible( true );
            return (int) $method->invoke( null, $text );
        } catch ( ReflectionException $e ) {
            // Method does not exist yet on unfixed code — use the same inline
            // logic that count_distinct_cjk_runs() will wrap.
            $ref   = new ReflectionClass( Turbo_Guard_SEO_Spam_Detector::class );
            $regex = $ref->getConstant( 'CJK_RUN_REGEX' );
            return (int) preg_match_all( $regex, $text );
        }
    }
}
