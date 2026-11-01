<?php
/**
 * PHPUnit bootstrap — stubs required WordPress globals, constants, and
 * functions so the plugin class can be loaded without a full WordPress
 * installation.
 */

// ─── Constants ────────────────────────────────────────────────────────────────
define( 'ABSPATH', __DIR__ . '/../' );
define( 'WP_CONTENT_DIR', __DIR__ . '/../' );
define( 'TURBO_GUARD_VERSION', '1.1.7' );
define( 'TURBO_GUARD_PLUGIN_DIR', __DIR__ . '/../' );
define( 'TURBO_GUARD_PLUGIN_FILE', __DIR__ . '/../turbo-guard.php' );
define( 'TURBO_GUARD_PLUGIN_URL', 'http://localhost/' );
define( 'TURBO_GUARD_PLUGIN_BASENAME', 'turbo-guard/turbo-guard.php' );
define( 'TURBO_GUARD_FREE_CLEANUP_LIMIT', 3 );
define( 'HOUR_IN_SECONDS', 3600 );

// ─── WordPress function stubs ─────────────────────────────────────────────────

if ( ! function_exists( 'get_option' ) ) {
    function get_option( $key, $default = false ) {
        return $default;
    }
}

if ( ! function_exists( 'update_option' ) ) {
    function update_option( $key, $value ) {
        return true;
    }
}

if ( ! function_exists( 'delete_transient' ) ) {
    function delete_transient( $key ) {
        return true;
    }
}

if ( ! function_exists( 'set_transient' ) ) {
    function set_transient( $key, $value, $expiration = 0 ) {
        return true;
    }
}

if ( ! function_exists( 'get_locale' ) ) {
    // Default to English (non-CJK) so tests run on a non-CJK-locale site.
    function get_locale() {
        return 'en_US';
    }
}

if ( ! function_exists( 'home_url' ) ) {
    function home_url( $path = '' ) {
        return 'http://localhost' . $path;
    }
}

if ( ! function_exists( 'wp_parse_url' ) ) {
    function wp_parse_url( $url, $component = -1 ) {
        return parse_url( $url, $component );
    }
}

if ( ! function_exists( 'wp_normalize_path' ) ) {
    function wp_normalize_path( $path ) {
        return str_replace( '\\', '/', $path );
    }
}

if ( ! function_exists( 'wp_upload_dir' ) ) {
    function wp_upload_dir() {
        return array( 'basedir' => sys_get_temp_dir() . '/turbo-guard-tests' );
    }
}

if ( ! function_exists( 'wp_strip_all_tags' ) ) {
    function wp_strip_all_tags( $text ) {
        return strip_tags( $text );
    }
}

if ( ! function_exists( 'get_permalink' ) ) {
    function get_permalink( $post_id ) {
        return 'http://localhost/?p=' . $post_id;
    }
}

if ( ! function_exists( 'get_edit_post_link' ) ) {
    function get_edit_post_link( $post_id ) {
        return 'http://localhost/wp-admin/post.php?post=' . $post_id . '&action=edit';
    }
}

if ( ! function_exists( 'get_post_types' ) ) {
    function get_post_types( $args = array(), $output = 'names' ) {
        return array( 'post', 'page' );
    }
}

if ( ! function_exists( 'size_format' ) ) {
    function size_format( $bytes ) {
        return $bytes . ' B';
    }
}

if ( ! function_exists( 'absint' ) ) {
    function absint( $value ) {
        return abs( (int) $value );
    }
}

if ( ! function_exists( 'sanitize_text_field' ) ) {
    function sanitize_text_field( $str ) {
        return trim( strip_tags( $str ) );
    }
}

if ( ! function_exists( 'current_time' ) ) {
    function current_time( $type ) {
        return ( 'mysql' === $type ) ? date( 'Y-m-d H:i:s' ) : time();
    }
}

if ( ! function_exists( 'apply_filters' ) ) {
    function apply_filters( $tag, $value, ...$args ) {
        return $value;
    }
}

if ( ! function_exists( 'do_action' ) ) {
    function do_action( $tag, ...$args ) {
        // no-op stub
    }
}

if ( ! function_exists( 'wp_cache_flush' ) ) {
    function wp_cache_flush() {
        return true;
    }
}

if ( ! function_exists( 'turbo_guard_is_pro' ) ) {
    function turbo_guard_is_pro() {
        return false;
    }
}

if ( ! function_exists( 'turbo_guard_clear_site_cache' ) ) {
    function turbo_guard_clear_site_cache() {
        // no-op stub for tests
    }
}

// ─── Stub for Turbo_Guard_Scanner (referenced by the SEO spam detector) ──────
if ( ! class_exists( 'Turbo_Guard_Scanner' ) ) {
    class Turbo_Guard_Scanner {
        public static function log_event( $event, $level, $message ) {
            // no-op stub
        }
        public static function is_trusted_upload_path( $path ) {
            return false;
        }
    }
}

// ─── Load the class under test ────────────────────────────────────────────────
require_once __DIR__ . '/../includes/class-turbo-guard-seo-spam-detector.php';
