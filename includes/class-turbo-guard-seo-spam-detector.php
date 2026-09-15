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

// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Security scanner requires direct database access.

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
		// Clear the site cache before scanning so results are fresh.
		turbo_guard_clear_site_cache();

		// Always clear old cached results before running fresh.
		delete_transient( 'turbo_guard_seo_spam_results' );
		$results = array(
			'spam_posts'      => array(),
			'spam_options'    => array(),
			'htaccess_hacks'  => array(),
			'spam_files'      => array(),
			'sitemap_entries' => array(),
			'google_link'     => '',
			'total'           => 0,
			'scanned_at'      => current_time( 'mysql' ),
		);

		$results['spam_posts']      = self::scan_posts_for_spam();
		$results['spam_options']    = self::scan_options_for_spam();
		$results['htaccess_hacks']  = self::scan_htaccess();
		$results['spam_files']      = self::scan_disk_for_spam();
		$results['sitemap_entries'] = self::scan_sitemap();
		$results['google_link']     = self::build_google_check_url();

		$results['total'] = count( $results['spam_posts'] )
			+ count( $results['spam_options'] )
			+ count( $results['htaccess_hacks'] )
			+ count( $results['spam_files'] )
			+ count( $results['sitemap_entries'] );

		// Cache for 6 hours.
		set_transient( 'turbo_guard_seo_spam_results', $results, 6 * HOUR_IN_SECONDS );

		// Log event.
		Turbo_Guard_Scanner::log_event(
			'seo_spam_scan',
			$results['total'] > 0 ? 'critical' : 'info',
			sprintf( 'SEO spam scan complete. %d spam indicators found.', $results['total'] )
		);

		// Let the Pro add-on extend results (AI analysis, auto-cleanup, etc.).
		do_action( 'turbo_guard_seo_spam_scan_complete', $results );

		// Send email alert if spam was found (Pro feature).
		if ( $results['total'] > 0 && turbo_guard_is_pro() && 'yes' === get_option( 'turbo_guard_notify_on_threats', 'yes' ) ) {
			self::send_seo_spam_alert( $results );
		}

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
		$batch_size = 200;
		$offset     = 0;

		// Paginate through ALL posts/pages so large sites are fully scanned.
		do {
			$posts = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT ID, post_title, post_type, post_status, post_date, guid, post_name
					 FROM {$wpdb->posts}
					 WHERE post_status IN ('publish','draft','private')
					 AND post_type IN ('post','page')
					 ORDER BY ID DESC
					 LIMIT %d OFFSET %d",
					$batch_size,
					$offset
				)
			);

			foreach ( $posts as $post ) {
				if ( self::is_ignored( 'posts', $post->ID ) ) {
					continue;
				}

				$is_spam      = false;
				$spam_reasons = array();

				// Check for CJK in title — only suspicious when the site itself is
				// NOT a Japanese/Chinese/Korean-language site.
				if ( ! self::is_cjk_site() && preg_match( self::CJK_REGEX, $post->post_title ) ) {
					$is_spam        = true;
					$spam_reasons[] = 'CJK characters in title';
				}

				// Check for spam keywords in title.
				$title_lower = strtolower( $post->post_title );
				foreach ( self::SPAM_KEYWORDS as $keyword ) {
					if ( false !== strpos( $title_lower, $keyword ) ) {
						$is_spam        = true;
						$spam_reasons[] = 'Spam keyword in title: ' . $keyword;
						break;
					}
				}

				// Check for spam keywords in the URL slug.
				$slug_lower = strtolower( $post->post_name );
				foreach ( self::SPAM_KEYWORDS as $keyword ) {
					if ( false !== strpos( $slug_lower, $keyword ) ) {
						$is_spam        = true;
						$spam_reasons[] = 'Spam keyword in URL slug: ' . $keyword;
						break;
					}
				}

				if ( $is_spam ) {
					$spam_posts[] = array(
						'id'       => $post->ID,
						'title'    => $post->post_title,
						'type'     => $post->post_type,
						'status'   => $post->post_status,
						'date'     => $post->post_date,
						'url'      => get_permalink( $post->ID ),
						'reasons'  => $spam_reasons,
						'edit_url' => get_edit_post_link( $post->ID ),
					);
				}
			}

			$offset += $batch_size;
		} while ( count( $posts ) === $batch_size );

		// Also search post content for CJK — skipped entirely on CJK-language
		// sites, where Japanese/Chinese/Korean text is legitimate.
		if ( ! self::is_cjk_site() ) {
			$content_offset = 0;
			do {
				$cjk_posts = $wpdb->get_results(
					$wpdb->prepare(
						"SELECT ID, post_title, post_type, post_status, guid
						 FROM {$wpdb->posts}
						 WHERE post_status = 'publish'
						 AND (post_content REGEXP %s OR post_excerpt REGEXP %s)
						 ORDER BY ID DESC
						 LIMIT %d OFFSET %d",
						'[\\x{3040}-\\x{30FF}\\x{4E00}-\\x{9FFF}]',
						'[\\x{3040}-\\x{30FF}\\x{4E00}-\\x{9FFF}]',
						$batch_size,
						$content_offset
					)
				);

				foreach ( $cjk_posts as $post ) {
					if ( self::is_ignored( 'posts', $post->ID ) ) {
						continue;
					}

					// Avoid duplicates.
					$existing_ids = array_column( $spam_posts, 'id' );
					if ( ! in_array( $post->ID, $existing_ids, true ) ) {
						$spam_posts[] = array(
							'id'       => $post->ID,
							'title'    => $post->post_title,
							'type'     => $post->post_type,
							'status'   => $post->post_status,
							'date'     => '',
							'url'      => get_permalink( $post->ID ),
							'reasons'  => array( 'CJK characters in post content' ),
							'edit_url' => get_edit_post_link( $post->ID ),
						);
					}
				}

				$content_offset += $batch_size;
			} while ( count( $cjk_posts ) === $batch_size );
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
			if ( self::is_ignored( 'options', $key ) ) {
				continue;
			}

			$value = get_option( $key, '' );
			if ( empty( $value ) ) {
				continue;
			}

			$reasons = array();
			if ( ! self::is_cjk_site() && preg_match( self::CJK_REGEX, $value ) ) {
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
		$htaccess   = ABSPATH . '.htaccess';

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
		$uploads_dir = wp_normalize_path( $uploads['basedir'] );

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
				$path    = wp_normalize_path( $file->getPathname() );
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
					// CJK alone is only suspicious when the site is not CJK-language.
					$has_cjk    = ( ! self::is_cjk_site() && preg_match( self::CJK_REGEX, $content ) );
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
					if ( ! self::is_cjk_site() && preg_match( self::CJK_REGEX, $content ) ) {
						$reasons[] = 'HTML file with Japanese/Chinese text in uploads';
					}
					$content_lower = strtolower( $content );
					foreach ( self::SPAM_KEYWORDS as $keyword ) {
						if ( false !== strpos( $content_lower, $keyword ) ) {
							$reasons[] = 'HTML file with spam keywords in uploads';
							break;
						}
					}
				} elseif ( 'js' === $ext ) {
					// JS files in uploads: flag CJK spam text, spam keywords, or obfuscation.
					if ( ! self::is_cjk_site() && preg_match( self::CJK_REGEX, $content ) ) {
						$reasons[] = 'JS file with Japanese/Chinese/Korean text in uploads';
					}
					$content_lower = strtolower( $content );
					foreach ( self::SPAM_KEYWORDS as $keyword ) {
						if ( false !== strpos( $content_lower, $keyword ) ) {
							$reasons[] = 'JS file with spam keywords in uploads';
							break;
						}
					}
					if ( preg_match( '/eval\s*\(|base64_decode\s*\(|gzinflate\s*\(/i', $content ) ) {
						$reasons[] = 'JS file with obfuscated code in uploads';
					}
				}

				if ( ! empty( $reasons ) ) {
					$rel_path = str_replace( wp_normalize_path( ABSPATH ), '', wp_normalize_path( $path ) );
					if ( self::is_ignored( 'files', $rel_path ) ) {
						continue;
					}

					$spam_files[] = array(
						'path'    => $rel_path,
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
	 * Scan the site's own sitemap(s) for spam-looking URLs.
	 *
	 * Makes a local HTTP request to the site itself — no external service.
	 * Handles both a flat sitemap and a one-level sitemap index.
	 *
	 * @since 1.4.0
	 * @return array Spam sitemap entries.
	 */
	private static function scan_sitemap() {
		$entries = array();

		$candidates = array(
			'wp-sitemap.xml',
			'sitemap.xml',
			'sitemap_index.xml',
			'sitemap-index.xml',
			'page-sitemap.xml',
			'post-sitemap.xml',
		);

		$sitemap_url = '';
		foreach ( $candidates as $candidate ) {
			$url  = home_url( $candidate );
			$resp = wp_remote_get( $url, array( 'timeout' => 10, 'redirection' => 3 ) );

			if ( is_wp_error( $resp ) ) {
				continue;
			}

			$code = wp_remote_retrieve_response_code( $resp );
			$body = wp_remote_retrieve_body( $resp );
			if ( 200 !== (int) $code || empty( $body ) ) {
				continue;
			}

			if ( false !== stripos( $body, '<sitemapindex' ) || false !== stripos( $body, '<loc>' ) ) {
				$sitemap_url = $url;
				break;
			}
		}

		if ( ! $sitemap_url ) {
			return $entries;
		}

		$urls = self::extract_sitemap_urls( $sitemap_url, 0 );

		foreach ( $urls as $entry_url ) {
			$path = (string) wp_parse_url( $entry_url, PHP_URL_PATH );
			if ( '' === $path ) {
				continue;
			}

			$reasons = array();

			if ( ! self::is_cjk_site() && preg_match( self::CJK_REGEX, rawurldecode( $path ) ) ) {
				$reasons[] = 'CJK characters in URL';
			}

			$path_lower = strtolower( $path );
			foreach ( self::SPAM_KEYWORDS as $keyword ) {
				if ( false !== strpos( $path_lower, $keyword ) ) {
					$reasons[] = 'Spam keyword in URL: ' . $keyword;
					break;
				}
			}

			if ( ! empty( $reasons ) ) {
				$entries[] = array(
					'url'     => $entry_url,
					'reasons' => $reasons,
				);
			}
		}

		return $entries;
	}

	/**
	 * Recursively extract <loc> URLs from a sitemap or sitemap index.
	 *
	 * @since 1.4.0
	 * @param string $url   Sitemap URL.
	 * @param int    $depth Recursion depth.
	 * @return array URL strings.
	 */
	private static function extract_sitemap_urls( $url, $depth ) {
		$urls = array();

		if ( $depth > 1 ) {
			return $urls; // Only follow one level of sitemap index.
		}

		$resp = wp_remote_get( $url, array( 'timeout' => 10, 'redirection' => 3 ) );
		if ( is_wp_error( $resp ) ) {
			return $urls;
		}

		$code = wp_remote_retrieve_response_code( $resp );
		$body = wp_remote_retrieve_body( $resp );
		if ( 200 !== (int) $code || empty( $body ) ) {
			return $urls;
		}

		// Sitemap index: follow each child sitemap (limited to first 10).
		if ( false !== stripos( $body, '<sitemapindex' ) ) {
			preg_match_all( '/<loc>\s*(.*?)\s*<\/loc>/is', $body, $matches );
			$child_maps = array_slice( $matches[1], 0, 10 );
			foreach ( $child_maps as $child ) {
				$child = trim( html_entity_decode( $child ) );
				if ( $child ) {
					$urls = array_merge( $urls, self::extract_sitemap_urls( $child, $depth + 1 ) );
				}
			}
			return array_unique( $urls );
		}

		preg_match_all( '/<loc>\s*(.*?)\s*<\/loc>/is', $body, $matches );
		foreach ( $matches[1] as $loc ) {
			$loc = trim( html_entity_decode( $loc ) );
			if ( $loc ) {
				$urls[] = $loc;
			}
		}

		return array_unique( $urls );
	}

	/**
	 * Read the SEO-spam ignore list.
	 *
	 * @since 1.4.0
	 * @return array {posts:[], options:[], files:[]}
	 */
	public static function get_ignored() {
		$ignored = get_option( 'turbo_guard_seo_spam_ignored', array() );
		if ( ! is_array( $ignored ) ) {
			$ignored = array();
		}

		return wp_parse_args(
			$ignored,
			array(
				'posts'   => array(),
				'options' => array(),
				'files'   => array(),
			)
		);
	}

	/**
	 * Whether an item is on the SEO-spam ignore list.
	 *
	 * @since 1.4.0
	 * @param string $bucket 'posts', 'options', or 'files'.
	 * @param mixed  $key    Post ID (int), option name (string), or file path (string).
	 * @return bool
	 */
	private static function is_ignored( $bucket, $key ) {
		$ignored = self::get_ignored();
		if ( empty( $ignored[ $bucket ] ) || ! is_array( $ignored[ $bucket ] ) ) {
			return false;
		}

		if ( 'posts' === $bucket ) {
			// Post IDs arrive as strings from $wpdb but are stored as ints.
			$key = absint( $key );
			foreach ( $ignored[ $bucket ] as $ignored_key ) {
				if ( absint( $ignored_key ) === $key ) {
					return true;
				}
			}
			return false;
		}

		return in_array( (string) $key, array_map( 'strval', $ignored[ $bucket ] ), true );
	}

	/**
	 * Add an item to the SEO-spam ignore list and drop it from cached results.
	 *
	 * @since 1.4.0
	 * @param string $bucket 'posts', 'options', or 'files'.
	 * @param mixed  $key    Post ID (int), option name (string), or file path (string).
	 * @return bool Success.
	 */
	public static function ignore_item( $bucket, $key ) {
		$allowed = array( 'posts', 'options', 'files' );
		if ( ! in_array( $bucket, $allowed, true ) ) {
			return false;
		}

		if ( 'posts' === $bucket ) {
			$key = absint( $key );
			if ( ! $key ) {
				return false;
			}
		} else {
			$key = sanitize_text_field( $key );
			if ( '' === $key ) {
				return false;
			}
		}

		$ignored = self::get_ignored();
		if ( ! in_array( $key, $ignored[ $bucket ], true ) ) {
			$ignored[ $bucket ][] = $key;
		}

		update_option( 'turbo_guard_seo_spam_ignored', $ignored );

		// Remove from the current cached results so the item disappears immediately.
		if ( 'posts' === $bucket ) {
			self::remove_from_results( 'spam_posts', $key );
		} elseif ( 'options' === $bucket ) {
			self::remove_from_results( 'spam_options', $key );
		} else {
			self::remove_from_results( 'spam_files', $key );
		}

		return true;
	}

	/**
	 * Remove an item from the cached scan results (used after delete/ignore).
	 *
	 * @since 1.4.0
	 * @param string $result_key One of spam_posts, spam_options, spam_files.
	 * @param mixed  $key        Identifier to match (id / option / path).
	 */
	private static function remove_from_results( $result_key, $key ) {
		$results = get_transient( 'turbo_guard_seo_spam_results' );
		if ( ! is_array( $results ) || empty( $results[ $result_key ] ) ) {
			return;
		}

		$id_field = 'spam_posts' === $result_key ? 'id' : ( 'spam_options' === $result_key ? 'option' : 'path' );

		$before = count( $results[ $result_key ] );
		$results[ $result_key ] = array_values(
			array_filter(
				$results[ $result_key ],
				function ( $item ) use ( $id_field, $key ) {
					return ( isset( $item[ $id_field ] ) && (string) $item[ $id_field ] !== (string) $key );
				}
			)
		);
		$after = count( $results[ $result_key ] );

		// Recalculate total.
		$results['total'] = max( 0, (int) $results['total'] - ( $before - $after ) );

		set_transient( 'turbo_guard_seo_spam_results', $results, 6 * HOUR_IN_SECONDS );
	}

	/**
	 * Number of spam posts a free user may clean (ceil 10%, minimum 1).
	 *
	 * @since 1.4.0
	 * @param int $total_spam_posts Total spam posts detected.
	 * @return int
	 */
	public static function free_deletable_count( $total_spam_posts ) {
		$total_spam_posts = absint( $total_spam_posts );
		if ( $total_spam_posts < 1 ) {
			return 0;
		}
		return max( 1, (int) ceil( $total_spam_posts * 0.10 ) );
	}

	/**
	 * Send email alert about SEO spam findings (Pro).
	 *
	 * @since 1.4.0
	 * @param array $results Scan results.
	 */
	private static function send_seo_spam_alert( $results ) {
		$email = get_option( 'turbo_guard_notify_admin_email', get_option( 'admin_email' ) );
		if ( ! $email ) {
			return;
		}

		$subject = sprintf(
			/* translators: 1: site name, 2: count */
			__( '[%1$s] Turbo Guard: %2$d SEO Spam Indicators Found', 'turbo-guard' ),
			get_bloginfo( 'name' ),
			$results['total']
		);

		$body = sprintf(
			/* translators: %d: number of SEO spam indicators */
			__( "Turbo Guard SEO spam scan found %d issue(s):\n\n", 'turbo-guard' ),
			$results['total']
		);

		foreach ( $results['spam_posts'] as $post ) {
			$body .= sprintf( "Post: %s (ID %d) — %s\n", $post['title'], $post['id'], implode( ', ', $post['reasons'] ) );
		}

		foreach ( $results['spam_files'] as $file ) {
			$body .= sprintf( "File: %s — %s\n", $file['path'], implode( ', ', $file['reasons'] ) );
		}

		foreach ( $results['sitemap_entries'] as $entry ) {
			$body .= sprintf( "Sitemap URL: %s — %s\n", $entry['url'], implode( ', ', $entry['reasons'] ) );
		}

		$body .= "\n" . sprintf(
			/* translators: %s: URL to view SEO spam details */
			__( 'View details: %s', 'turbo-guard' ),
			admin_url( 'admin.php?page=turbo-guard-seo-spam' )
		);

		wp_mail( $email, $subject, $body );
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
	 * Whether the site's own language is Japanese/Chinese/Korean.
	 *
	 * On CJK-language sites, Japanese/Chinese/Korean text is legitimate content,
	 * so the detector must NOT flag CJK text alone as spam — this prevents the
	 * most common false positive on shared hosting and international sites.
	 *
	 * @since 1.3.0
	 * @return bool
	 */
	private static function is_cjk_site() {
		// Manual override for sites with legitimate CJK content.
		if ( 'yes' === get_option( 'turbo_guard_seo_allow_cjk_content', 'no' ) ) {
			return true;
		}

		$locale = strtolower( get_locale() );
		return ( 0 === strpos( $locale, 'ja' )
			|| 0 === strpos( $locale, 'zh' )
			|| 0 === strpos( $locale, 'ko' ) );
	}

	/**
	 * Delete or trash a spam post.
	 *
	 * @since 1.2.0
	 * @since 1.4.0 Added $mode (trash|delete); trash is default and recoverable.
	 *
	 * @param int    $post_id WordPress post ID.
	 * @param string $mode    'trash' (default) or 'delete' (permanent, Pro).
	 * @return bool Success.
	 */
	public static function delete_spam_post( $post_id, $mode = 'trash' ) {
		$post_id = absint( $post_id );
		if ( ! $post_id ) {
			return false;
		}

		$mode = ( 'delete' === $mode ) ? 'delete' : 'trash';

		$result = ( 'delete' === $mode )
			? wp_delete_post( $post_id, true )
			: wp_trash_post( $post_id );

		if ( $result ) {
			Turbo_Guard_Scanner::log_event(
				'spam_post_deleted',
				'warning',
				sprintf(
					/* translators: 1: action taken, 2: post ID */
					__( 'Spam post %1$s: ID %2$d', 'turbo-guard' ),
					( 'delete' === $mode ? __( 'deleted permanently', 'turbo-guard' ) : __( 'moved to trash', 'turbo-guard' ) ),
					$post_id
				)
			);

			// Update cached results so the row disappears without a full re-scan.
			self::remove_from_results( 'spam_posts', $post_id );
		}

		return (bool) $result;
	}
}
