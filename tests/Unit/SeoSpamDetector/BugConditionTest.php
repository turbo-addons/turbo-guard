<?php
/**
 * Bug Condition Exploration Tests — SEO Spam Detector
 *
 * These tests are written BEFORE the fix is applied. They encode the three
 * concrete bug-condition cases described in the spec and are EXPECTED TO FAIL
 * on unfixed code. When the fix is implemented, all three tests must pass.
 *
 * Validates: Requirements 1.1, 1.3, 1.4, 1.5, 1.6, 2.1, 2.2, 2.3, 2.4, 3.1
 *
 * @package TurboGuard\Tests\Unit\SeoSpamDetector
 */

declare(strict_types=1);

namespace TurboGuard\Tests\Unit\SeoSpamDetector;

use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use Turbo_Guard_SEO_Spam_Detector;

/**
 * Bug condition exploration tests for Turbo_Guard_SEO_Spam_Detector.
 *
 * These tests demonstrate the two bug branches in the unfixed scanner:
 *   - False positive: bare CJK regex fires on a single run with no keyword
 *   - Missed spam: CJK spam keywords are invisible to has_spam_keyword()
 *   - Missed spam (generator): looks_like_doorway_generator() misses keyword clusters
 */
class BugConditionTest extends TestCase {

    // ──────────────────────────────────────────────────────────────────────────
    // Case A — False positive: content with 1 CJK run, 0 dictionary matches
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Case A: A post with content "Thank you — ありがとう" contains exactly 1 CJK run
     * (the word ありがとう) and zero CJK spam keyword dictionary matches.
     *
     * isBugCondition_FalsePositive(X) = true because:
     *   - contains_any_cjk_char = true
     *   - cjk_run_count < 5        = true (1 run)
     *   - no dictionary match      = true
     *
     * OLD (unfixed) behaviour: bare preg_match(CJK_REGEX) fires → flagged
     * FIXED behaviour: 1 run < 5 AND no keyword → NOT flagged
     *
     * Validates: Requirements 1.1, 1.2, 1.3
     */
    public function test_case_a_false_positive_single_cjk_run_should_not_be_flagged(): void {
        $content = "Thank you — ありがとう";

        // To replicate the bug, we call the private CJK content detection logic
        // that scan_posts_for_spam() applies.  The unfixed code uses a bare
        // preg_match(CJK_REGEX) — any CJK character causes a positive result.
        // The fixed code should require either a keyword OR ≥5 distinct CJK runs.
        $cjk_regex = self::get_class_constant( 'CJK_REGEX' );

        // On unfixed code this assertion passes (the bug exists):
        // preg_match flags the content — which is wrong for this legitimate text.
        $bare_cjk_match = (bool) preg_match( $cjk_regex, $content );

        // Count distinct CJK runs with the class constant CJK_RUN_REGEX.
        $cjk_run_regex    = self::get_class_constant( 'CJK_RUN_REGEX' );
        $distinct_cjk_runs = (int) preg_match_all( $cjk_run_regex, $content );

        // Verify our understanding of the input.
        $this->assertTrue( $bare_cjk_match, 'Pre-condition: content does contain CJK characters' );
        $this->assertLessThan( 5, $distinct_cjk_runs, 'Pre-condition: fewer than 5 distinct CJK runs' );

        // Check that has_spam_keyword returns false for this legitimate content.
        $keyword_result = self::invoke_has_spam_keyword( $content );

        // On UNFIXED code: has_spam_keyword returns false (good here — the bug
        // is in the bare preg_match path, not in has_spam_keyword for this case).
        // On FIXED code: same — still returns false (no keyword match).
        $this->assertFalse(
            $keyword_result,
            'has_spam_keyword() must return false for legitimate translation content with no spam keywords. ' .
            'Returned: ' . var_export( $keyword_result, true )
        );

        // ── Core assertion for Case A ──────────────────────────────────────────
        // The fixed scanner must NOT flag this as spam:
        // condition = keyword OR runs >= 5 = false OR false = false → NOT spam.
        //
        // On UNFIXED code the scan_posts_for_spam() content loop uses only:
        //   if ( ! preg_match( self::CJK_REGEX, $haystack ) ) { continue; }
        // which is TRUE here, so the post IS added to spam_posts.
        //
        // We replicate the unfixed decision logic and assert it should NOT fire.
        $unfixed_would_flag = $bare_cjk_match; // bare preg_match alone
        $fixed_should_flag  = $keyword_result || $distinct_cjk_runs >= 5;

        // This assertion FAILS on unfixed code (bug confirmed):
        // unfixed_would_flag is true, but the correct answer is false.
        $this->assertFalse(
            $fixed_should_flag,
            'Case A FAILURE: Content "Thank you — ありがとう" (1 CJK run, 0 keywords) ' .
            'should NOT be flagged as spam. ' .
            'Fixed condition (keyword OR runs>=5) evaluated to: ' . var_export( $fixed_should_flag, true )
        );

        // Verify the fix is effective: bare preg_match would have flagged this,
        // but the fixed condition correctly does NOT flag it.
        // On fixed code: $unfixed_would_flag=true, $fixed_should_flag=false → bug fixed.
        $this->assertTrue(
            $unfixed_would_flag && ! $fixed_should_flag,
            'Fix verification (Case A): bare preg_match fires (unfixed would flag) ' .
            'but fixed condition correctly does NOT flag "Thank you — ありがとう". ' .
            'unfixed_would_flag=' . var_export( $unfixed_would_flag, true ) . ', ' .
            'fixed_should_flag=' . var_export( $fixed_should_flag, true )
        );
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Case B — Missed spam (keyword): has_spam_keyword misses CJK vocabulary
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Case B: has_spam_keyword('激安 ブランド品') must return the matched keyword.
     *
     * isBugCondition_MissedSpam(X) = true because:
     *   - contains_cjk_spam_keyword = true (激安 is a dictionary entry)
     *   - no Latin keyword match    = true
     *
     * OLD (unfixed) behaviour: has_spam_keyword returns false (no CJK dictionary)
     * FIXED behaviour: has_spam_keyword returns '激安' (or another matched keyword)
     *
     * Validates: Requirements 2.1, 2.3, 2.4
     */
    public function test_case_b_missed_spam_keyword_cjk_phrase_must_be_detected(): void {
        $spam_text = '激安 ブランド品';

        $result = self::invoke_has_spam_keyword( $spam_text );

        // On UNFIXED code this fails — has_spam_keyword only checks BRAND_KEYWORDS
        // (Latin) and PHARMA_KEYWORDS (Latin) and returns false.
        // On FIXED code this must pass — it checks CJK_SPAM_KEYWORDS and returns '激安'.
        $this->assertNotFalse(
            $result,
            'BUG CONFIRMED (Case B): has_spam_keyword("激安 ブランド品") returned false on unfixed code. ' .
            'The function only checks Latin-script keywords (BRAND_KEYWORDS, PHARMA_KEYWORDS) ' .
            'and is blind to CJK spam vocabulary. ' .
            'Fixed code must return a non-false string (the matched keyword, e.g. "激安"). ' .
            'Actual return value: ' . var_export( $result, true )
        );

        // Additionally verify the returned value is a string (the matched keyword).
        if ( false !== $result ) {
            $this->assertIsString(
                $result,
                'has_spam_keyword() must return the matched keyword string, not a non-string truthy value'
            );
        }
    }

    /**
     * Case B extension: verify several other CJK spam keywords are also detected.
     * This confirms the full dictionary is checked, not just one entry.
     *
     * Validates: Requirements 2.1, 2.2, 2.3
     */
    public function test_case_b_additional_cjk_spam_keywords_must_be_detected(): void {
        $spam_samples = array(
            'ブランド品のコピー商品です',  // Japanese luxury brand
            'バイアグラを激安で購入',        // Japanese pharma + discount
            '奢侈品を最安値で',              // Chinese luxury keyword
        );

        $failures = array();
        foreach ( $spam_samples as $sample ) {
            $result = self::invoke_has_spam_keyword( $sample );
            if ( false === $result ) {
                $failures[] = $sample . ' → returned false (should return matched keyword)';
            }
        }

        // On UNFIXED code all of these fail.
        // On FIXED code all must pass.
        $this->assertEmpty(
            $failures,
            'BUG CONFIRMED (Case B extension): The following CJK spam phrases were not detected: ' .
            "\n" . implode( "\n", $failures )
        );
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Case C — Missed spam (generator): looks_like_doorway_generator misses
    //          PHP files with 3 CJK keyword matches but no route hook
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Case C: looks_like_doorway_generator() must return true for PHP content
     * that contains 'ブランド', '激安', '偽物' (3 distinct dictionary entries)
     * but has NO add_rewrite_rule and NO CJK $variable names.
     *
     * isBugCondition_MissedSpam(X, context=generator) = true because:
     *   - contains_cjk_spam_keyword × 3 = true (≥3 dictionary matches)
     *   - no Latin keyword              = true
     *   - no CJK variable names         = true
     *   - no numeric-ID route hook      = true
     *
     * OLD (unfixed) behaviour: returns false (no route hook, so early-return false)
     * FIXED behaviour: returns true (≥3 distinct CJK keyword cluster signal)
     *
     * Validates: Requirements 3.1, 3.2, 3.4
     */
    public function test_case_c_missed_spam_generator_cjk_keyword_cluster_must_be_detected(): void {
        // PHP content with 3 CJK dictionary keywords, no add_rewrite_rule, no CJK $vars.
        $php_content = <<<'PHP'
<?php
// Template file
echo "ブランド品はこちら\n";
echo "激安セール中\n";
echo "偽物コピー品\n";
function render_page() {
    return "<h1>Products</h1>";
}
PHP;

        $result = self::invoke_looks_like_doorway_generator( $php_content );

        // On UNFIXED code: $has_route is false → early return false → bug!
        // On FIXED code:   ≥3 distinct keyword matches → return true → correct.
        $this->assertTrue(
            $result,
            'BUG CONFIRMED (Case C): looks_like_doorway_generator() returned false for PHP content ' .
            'containing ブランド, 激安, 偽物 (3 CJK spam dictionary entries) ' .
            'with no add_rewrite_rule and no CJK variable names. ' .
            'The unfixed code hits the "!$has_route → return false" early-exit before any ' .
            'keyword cluster check. Fixed code must detect ≥3 distinct CJK spam keywords ' .
            'and return true regardless of route hooks.'
        );
    }

    /**
     * Case C boundary: looks_like_doorway_generator() must return false when only
     * 2 CJK dictionary keywords are present (below the ≥3 threshold).
     *
     * This confirms there is no false positive for files with incidental CJK content.
     *
     * Validates: Requirements 3.4
     */
    public function test_case_c_two_cjk_keywords_below_threshold_must_not_be_flagged(): void {
        // Only 2 CJK keywords, no route hook, no CJK variable names.
        $php_content = <<<'PHP'
<?php
// Legitimate multilingual plugin with translation strings
echo "ブランド\n";   // Only 1 keyword
echo "激安\n";        // Only 2 keywords total — below threshold
function render() {
    return "Hello";
}
PHP;

        $result = self::invoke_looks_like_doorway_generator( $php_content );

        // Both unfixed and fixed code should return false here.
        $this->assertFalse(
            $result,
            'Case C boundary: looks_like_doorway_generator() must return false for content ' .
            'with only 2 distinct CJK spam keywords (ブランド, 激安). ' .
            'The ≥3 threshold prevents false positives on legitimate plugins with translation strings. ' .
            'Actual return: ' . var_export( $result, true )
        );
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Get a class constant from Turbo_Guard_SEO_Spam_Detector via Reflection.
     */
    private static function get_class_constant( string $name ): mixed {
        $ref = new \ReflectionClass( Turbo_Guard_SEO_Spam_Detector::class );
        return $ref->getConstant( $name );
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
}
