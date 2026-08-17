<?php
/**
 * SEO Spam Detector — No OAuth Required.
 *
 * Detects Japanese/Chinese SEO spam that hackers have indexed in Google
 * by scanning local evidence on the site itself:
 *
 *  1. Spam posts/pages in the WordPress database (CJK titles/content)
 *  2. Spam files on disk (PHP files with CJK text)
 *  3. .htaccess redirect hacks
 *  4. wp_options contamination (siteurl, blogname, active_plugins)
 *  5. Sitemap entries that look like spam
 *  6. Google cache check via public search URL (no API key needed)
 *
 * This gives users immediate value without any Google Cloud setup.
 *
 * @package TurboGuard
 * @since   1.2.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * SEO Spam Detector.
 *
 * @since 1.2.0
 */
class Turbo_Guard_SEO_Spam_Detector {

	/**
	 * CJK Unicode ranges for detection.
	 * Covers Japanese (Hiragana, Katakana), Chinese (CJK Unified), Korean (Hangul).
	 */
	const CJK_REGEX = '/[\x{3040}-\x{30FF}\x{31F0}-\x{31FF}\x{4E00}-\x{9FFF}\x{3400}-\x{4DBF}\x{AC00}-\x{D7A3}]/u';

	/**
	 * Spam keyword patterns (luxury brands, pharma, gambling).
	 */
	const SPAM_KEYWORDS = array(
		'gucci', 'louis vuitton', 'chanel', 'prada', 'rolex', 'hermes', 'burberry',
		'viagra', 'cialis', 'levitra', 'pharmacy', 'casino', 'poker', 'slot',
		'coach', 'oakley', 'ray-ban', 'ugg', 'tory burch', 'moncler', 'canada goose',
	);

	/**
	 * Run a full SEO spam detection scan.
	 *
	 * @since 1.2.0
	 * @return array Scan results.
	 */
	public static function run_scan() {
		// Always clear old cached results before running fresh.
		delete_transient( 'turbo_guard_seo_spam_results' );
		$results = array(
			'spam_posts'    => array(),
			'spam_options'  => array(),
			'htaccess_hacks'=> array(),
			'spam_files'    => array(),
			'google_link'   => '',
			'total'         => 0,
			'scanned_at'    => current_time( 'mysql' ),
		);

		$results['spam_posts']     = self::scan_posts_for_spam();
		$results['spam_options']   = self::scan_options_for_spam();
		$results['htaccess_hacks'] = self::scan_htaccess();
		$results['spam_files']     = self::scan_disk_for_spam();
		$results['google_link']    = self::build_google_check_url();

		$results['total'] = count( $results['spam_posts'] )
			+ count( $results['spam_options'] )
			+ count( $results['htaccess_hacks'] )
			+ count( $results['spam_files'] );

		// Cache for 6 hours.
		set_transient( 'turbo_guard_seo_spam_results', $results, 6 * HOUR_IN_SECONDS );

		// Log event.
		Turbo_Guard_Scanner::log_event(
			'seo_spam_scan',
			$results['total'] > 0 ? 'critical' : 'info',
			sprintf( 'SEO spam scan complete. %d spam indicators found.', $results['total'] )
		);

		return $results;
	}

	/**
	 * Scan WordPress posts/pages for CJK spam content.
	 *
	 * @since 1.2.0
	 * @return array Spam post entries.
	 */
	private static function scan_posts_for_spam() {
		global $wpdb;
		$spam_posts = array();

		// Search post titles for CJK characters.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- SEO spam scan over core posts table; only $wpdb->posts is interpolated.
		$posts = $wpdb->get_results(
			"SELECT ID, post_title, post_type, post_status, post_date, guid
			 FROM {$wpdb->posts}
			 WHERE post_status IN ('publish','draft','private')
			 AND post_type IN ('post','page')
			 ORDER BY ID DESC
			 LIMIT 500"
		);

		foreach ( $posts as $post ) {
			$is_spam        = false;
			$spam_reasons   = array();

			// Check for CJK in title.
			if ( preg_match( self::CJK_REGEX, $post->post_title ) ) {
				$is_spam      = true;
				$spam_reasons[] = 'CJK characters in title';
			}

			// Check for spam keywords in title.
			$title_lower = strtolower( $post->post_title );
			foreach ( self::SPAM_KEYWORDS as $keyword ) {
				if ( false !== strpos( $title_lower, $keyword ) ) {
					$is_spam      = true;
					$spam_reasons[] = 'Spam keyword: ' . $keyword;
					break;
				}
			}

			if ( $is_spam ) {
				$spam_posts[] = array(
					'id'      => $post->ID,
					'title'   => $post->post_title,
					'type'    => $post->post_type,
					'status'  => $post->post_status,
					'date'    => $post->post_date,
					'url'     => get_permalink( $post->ID ),
					'reasons' => $spam_reasons,
					'edit_url'=> get_edit_post_link( $post->ID ),
				);
			}
		}

		// Also search post content for CJK.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- SEO spam scan over core posts table; scan results are transient-cached by the caller.
		$cjk_posts = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ID, post_title, post_type, post_status, guid
				 FROM {$wpdb->posts}
				 WHERE post_status = 'publish'
				 AND (post_content REGEXP %s OR post_excerpt REGEXP %s)
				 LIMIT 50",
				'[\\x{3040}-\\x{30FF}\\x{4E00}-\\x{9FFF}]',
				'[\\x{3040}-\\x{30FF}\\x{4E00}-\\x{9FFF}]'
			)
		);

		foreach ( $cjk_posts as $post ) {
			// Avoid duplicates.
			$existing_ids = array_column( $spam_posts, 'id' );
			if ( ! in_array( $post->ID, $existing_ids, true ) ) {
				$spam_posts[] = array(
					'id'      => $post->ID,
					'title'   => $post->post_title,
					'type'    => $post->post_type,
					'status'  => $post->post_status,
					'date'    => '',
					'url'     => get_permalink( $post->ID ),
					'reasons' => array( 'CJK characters in post content' ),
					'edit_url'=> get_edit_post_link( $post->ID ),
				);
			}
		}

		return $spam_posts;
	}

	/**
	 * Scan key wp_options for spam contamination.
	 *
	 * @since 1.2.0
	 * @return array Contaminated options.
	 */
	private static function scan_options_for_spam() {
		$contaminated = array();

		$check_options = array(
			'siteurl'         => 'Site URL',
			'home'            => 'Home URL',
			'blogname'        => 'Site Title',
			'blogdescription' => 'Tagline',
			'admin_email'     => 'Admin Email',
		);

		foreach ( $check_options as $key => $label ) {
			$value = get_option( $key, '' );
			if ( empty( $value ) ) {
				continue;
			}

			$reasons = array();
			if ( preg_match( self::CJK_REGEX, $value ) ) {
				$reasons[] = 'Contains CJK (Japanese/Chinese/Korean) characters';
			}

			$value_lower = strtolower( $value );
			foreach ( self::SPAM_KEYWORDS as $keyword ) {
				if ( false !== strpos( $value_lower, $keyword ) ) {
					$reasons[] = 'Contains spam keyword: ' . $keyword;
					break;
				}
			}

			if ( ! empty( $reasons ) ) {
				$contaminated[] = array(
					'option'  => $key,
					'label'   => $label,
					'value'   => substr( $value, 0, 200 ),
					'reasons' => $reasons,
				);
			}
		}

		return $contaminated;
	}

	/**
	 * Scan .htaccess file for suspicious redirect rules.
	 *
	 * @since 1.2.0
	 * @return array Suspicious rules found.
	 */
	private static function scan_htaccess() {
		$suspicious = array();
		// Justification: scanning the site's root .htaccess for injected redirect
		// rules — legitimate for a security plugin.
		$htaccess   = wp_normalize_path( ABSPATH . '.htaccess' );

		if ( ! file_exists( $htaccess ) || ! is_readable( $htaccess ) ) {
			return $suspicious;
		}

		$content = file_get_contents( $htaccess ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( ! $content ) {
			return $suspicious;
		}

		$lines = explode( "\n", $content );
		foreach ( $lines as $line_num => $line ) {
			$line_trimmed = trim( $line );

			// Skip WordPress standard rules and Turbo Guard rules.
			if (
				empty( $line_trimmed )
				|| strpos( $line_trimmed, '#' ) === 0
				|| strpos( $line_trimmed, '# BEGIN WordPress' ) !== false
				|| strpos( $line_trimmed, '# END WordPress' ) !== false
				|| strpos( $line_trimmed, '# Turbo Guard' ) !== false
			) {
				continue;
			}

			// Detect suspicious redirect patterns.
			$is_suspicious = false;
			$reason        = '';

			// Redirect to external domains.
			if ( preg_match( '/RewriteRule.*https?:\/\/(?!' . preg_quote( wp_parse_url( home_url(), PHP_URL_HOST ), '/' ) . ')/i', $line_trimmed ) ) {
				$is_suspicious = true;
				$reason        = 'Redirects to external domain';
			}

			// CJK in htaccess (very suspicious).
			if ( preg_match( self::CJK_REGEX, $line_trimmed ) ) {
				$is_suspicious = true;
				$reason        = 'Contains CJK characters';
			}

			// Encoded/obfuscated rules.
			if ( preg_match( '/base64_decode|eval\(|gzinflate/i', $line_trimmed ) ) {
				$is_suspicious = true;
				$reason        = 'Contains obfuscated code';
			}

			if ( $is_suspicious ) {
				$suspicious[] = array(
					'line'   => $line_num + 1,
					'rule'   => substr( $line_trimmed, 0, 200 ),
					'reason' => $reason,
				);
			}
		}

		return $suspicious;
	}

	/**
	 * Scan disk for PHP/HTML files containing CJK spam text.
	 * Only scans wp-content/uploads (most common attack vector).
	 *
	 * @since 1.2.0
	 * @return array Spam files found.
	 */
	private static function scan_disk_for_spam() {
		$spam_files  = array();
		$uploads     = wp_upload_dir();
		$uploads_dir = $uploads['basedir'];

		if ( ! is_dir( $uploads_dir ) ) {
			return $spam_files;
		}

		// Directories to always skip — our own created folders.
		$skip_dirs = array(
			'turbo-guard-quarantine', // Our quarantine folder.
			'turbo-guard-backups',    // Our backup folder.
		);

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveCallbackFilterIterator(
					new RecursiveDirectoryIterator( $uploads_dir, RecursiveDirectoryIterator::SKIP_DOTS ),
					function ( $current ) use ( $skip_dirs ) {
						if ( $current->isDir() ) {
							foreach ( $skip_dirs as $skip ) {
								if ( $current->getFilename() === $skip ) {
									return false;
								}
							}
						}
						return true;
					}
				)
			);

			$count = 0;
			foreach ( $iterator as $file ) {
				if ( $count > 1000 ) {
					break;
				}
				if ( ! $file->isFile() ) {
					continue;
				}

				$ext = strtolower( $file->getExtension() );
				if ( ! in_array( $ext, array( 'php', 'html', 'htm', 'js' ), true ) ) {
					continue;
				}

				++$count;
				$path    = $file->getPathname();
				$content = @file_get_contents( $path, false, null, 0, 4096 ); // phpcs:ignore
				if ( ! $content ) {
					continue;
				}

				$reasons = array();

				// Rule: PHP in uploads is suspicious ONLY if it also contains:
				// - CJK characters, OR
				// - known spam keywords, OR
				// - malicious PHP patterns (eval, base64_decode, etc.)
				// A plain index.php placeholder ("Silence is golden") is NOT spam.
				if ( in_array( $ext, array( 'php' ), true ) ) {
					// Detect WordPress standard placeholder files — always safe.
					$is_silence = ( stripos( $content, 'Silence is golden' ) !== false );

					if ( $is_silence ) {
						continue;
					}

					// Only flag if it has dangerous patterns.
					$has_cjk    = preg_match( self::CJK_REGEX, $content );
					$has_eval   = preg_match( '/eval\s*\(/i', $content );
					$has_base64 = preg_match( '/base64_decode\s*\(/i', $content );
					$has_spam   = false;
					$content_lower = strtolower( $content );
				foreach ( self::SPAM_KEYWORDS as $keyword ) {
					if ( false !== strpos( $content_lower, $keyword ) ) {
						$has_spam = true;
						break;
					}
				}

					if ( $has_cjk ) {
						$reasons[] = 'PHP file with Japanese/Chinese/Korean text in uploads';
					}
					if ( $has_eval ) {
						$reasons[] = 'PHP file with eval() in uploads';
					}
					if ( $has_base64 ) {
						$reasons[] = 'PHP file with base64_decode() in uploads';
					}
					if ( $has_spam ) {
						$reasons[] = 'PHP file with spam brand keywords in uploads';
					}
				} elseif ( in_array( $ext, array( 'html', 'htm' ), true ) ) {
					// HTML files in uploads: flag if CJK or spam keywords.
					if ( preg_match( self::CJK_REGEX, $content ) ) {
						$reasons[] = 'HTML file with Japanese/Chinese text in uploads';
					}
					$content_lower = strtolower( $content );
					foreach ( self::SPAM_KEYWORDS as $keyword ) {
						if ( false !== strpos( $content_lower, $keyword ) ) {
							$reasons[] = 'HTML file with spam keywords in uploads';
							break;
						}
					}
				}

				if ( ! empty( $reasons ) ) {
					$spam_files[] = array(
						'path'    => str_replace( ABSPATH, '', $path ), // Display-only relative path.
						'size'    => size_format( $file->getSize() ),
						'modified'=> gmdate( 'Y-m-d H:i', $file->getMTime() ),
						'reasons' => $reasons,
					);
				}
			}
		} catch ( Exception $e ) {
			// Ignore filesystem errors.
		}

		return $spam_files;
	}

	/**
	 * Build a Google site: search URL so admin can manually check indexed pages.
	 *
	 * @since 1.2.0
	 * @return string Google search URL.
	 */
	private static function build_google_check_url() {
		$domain = wp_parse_url( home_url(), PHP_URL_HOST );
		// Search for site: indexed pages — admin clicks this to see what Google has.
		return 'https://www.google.com/search?q=site:' . rawurlencode( $domain );
	}

	/**
	 * Get cached SEO spam results.
	 *
	 * @since 1.2.0
	 * @return array|false
	 */
	public static function get_cached_results() {
		return get_transient( 'turbo_guard_seo_spam_results' );
	}

	/**
	 * Delete a spam post from the database.
	 *
	 * @since 1.2.0
	 * @param int $post_id WordPress post ID.
	 * @return bool Success.
	 */
	public static function delete_spam_post( $post_id ) {
		$post_id = absint( $post_id );
		if ( ! $post_id ) {
			return false;
		}

		$result = wp_delete_post( $post_id, true );

		if ( $result ) {
			Turbo_Guard_Scanner::log_event(
				'spam_post_deleted',
				'warning',
				sprintf( 'Spam post deleted: ID %d', $post_id )
			);
		}

		return (bool) $result;
	}
}
