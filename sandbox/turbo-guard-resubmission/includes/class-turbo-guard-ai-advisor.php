<?php
/**
 * AI Security Advisor Class.
 *
 * Analyzes scan results, firewall logs, and traffic patterns to generate
 * intelligent, plain-English security reports with actionable recommendations.
 *
 * Like Heidi Health for doctors, Turbo Guard AI removes the confusing,
 * technical security work from WordPress site owners so they can focus
 * on running their business - not fighting hackers.
 *
 * Works in two modes:
 *  1. Built-in AI  - rule-based analysis, 100% free, no API key needed.
 *  2. OpenAI mode  - sends anonymised scan summary to OpenAI GPT for richer
 *                    narrative; requires the user to provide their own API key.
 *
 * @package TurboGuard
 * @since   1.2.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * AI Security Advisor.
 *
 * @since 1.2.0
 */
class Turbo_Guard_AI_Advisor {

	/**
	 * Known attack campaign fingerprints.
	 *
	 * Each entry maps observable threat types to a named campaign with
	 * a plain-English explanation and step-by-step remediation guide.
	 *
	 * @var array[]
	 */
	private static $attack_patterns = array(

		'japanese_seo_spam' => array(
			'name'        => 'Japanese / Chinese SEO Spam Campaign',
			'indicators'  => array( 'cjk_spam_japanese', 'cjk_spam_chinese', 'seo_spam_php', 'luxury_spam_keywords' ),
			'severity'    => 'critical',
			'explanation' => 'Attackers injected Japanese or Chinese e-commerce spam into your site. These files create fake product pages (GUCCI bags, luxury items) that get indexed by Google - damaging your domain reputation and SEO rankings. Files are hidden so English-speaking owners do not notice them.',
			'impact'      => array(
				'Google may blacklist your domain',
				'Your site ranks for Japanese spam keywords instead of real content',
				'Visitors get redirected to scam shopping sites',
				'Your hosting provider may suspend your account',
			),
			'steps'       => array(
				'Delete all flagged files using the Bulk Delete button above.',
				'Go to GSC Cleanup and remove all indexed spam URLs from Google.',
				'Use the .htaccess generator to redirect old spam URLs to your homepage.',
				'Update ALL plugins and themes immediately - the attacker entered through a vulnerability.',
				'Change all WordPress admin passwords.',
				'Enable Two-Factor Authentication on all admin accounts.',
				'Run the Vulnerability Scanner to find which plugin or theme was exploited.',
			),
		),

		'backdoor_webshell' => array(
			'name'        => 'Web Shell / Backdoor Installation',
			'indicators'  => array( 'eval_base64', 'eval_gzinflate', 'c99shell', 'r57shell', 'webshell', 'phpspy' ),
			'severity'    => 'critical',
			'explanation' => 'A web shell (backdoor) has been installed on your server. This gives the attacker a persistent remote control interface. They can read, write, or delete any file on your site, create admin accounts, send spam email, or use your server to attack other websites. This is the most serious type of WordPress compromise.',
			'impact'      => array(
				'Full server access for the attacker at any time',
				'All files and database can be read, modified, or deleted',
				'Your server may be used to send spam or mine cryptocurrency',
				'Hosting suspension and potential legal liability',
			),
			'steps'       => array(
				'DELETE the flagged files immediately - do not just quarantine them.',
				'Change your WordPress admin password and all database passwords right now.',
				'Go to Users and check for any admin accounts you did not create.',
				'Check your .htaccess file for any redirect rules you did not add.',
				'Contact your hosting provider and request a server-side security audit.',
				'Consider restoring from a clean backup if one is available.',
				'Enable 2FA on all admin accounts immediately.',
				'Run the Vulnerability Scanner - the shell was installed via a known CVE.',
			),
		),

		'brute_force_campaign' => array(
			'name'        => 'Brute Force Login Campaign',
			'indicators'  => array( 'brute_force_detected', 'failed_logins_high' ),
			'severity'    => 'high',
			'explanation' => 'Your site is being targeted by automated password-guessing attacks. Bots are systematically trying thousands of username and password combinations to gain admin access. Turbo Guard brute force protection is blocking these attempts, but the attacks are ongoing.',
			'impact'      => array(
				'Admin account takeover if a weak password is guessed',
				'Server performance degraded by high login attempt volume',
				'Risk of eventual success if passwords are not strong enough',
			),
			'steps'       => array(
				'Enable Two-Factor Authentication on your profile page.',
				'Ensure all admin users have strong, unique passwords (12+ characters).',
				'Consider changing your WordPress login URL in Settings.',
				'Block the attacking IP ranges in Firewall using CIDR notation.',
				'Review Live Traffic to identify the attacking IP range.',
			),
		),

		'seo_spam_db_injection' => array(
			'name'        => 'Database SEO Spam Injection',
			'indicators'  => array( 'db_pharma_spam', 'db_casino_spam', 'db_hidden_content', 'db_js_eval' ),
			'severity'    => 'critical',
			'explanation' => 'Spam content has been injected directly into your WordPress database - typically into post content, widgets, or site options. This technique is harder to detect than file-based attacks because the malicious content looks like regular post data. The injected content usually includes hidden links to pharma, gambling, or luxury goods websites.',
			'impact'      => array(
				'Hidden links boost attacker-owned spam sites',
				'Google penalises your site for hosting spam content',
				'Visitors see unexpected content or get redirected',
			),
			'steps'       => array(
				'Use phpMyAdmin or WP-CLI to review and clean the flagged posts and options.',
				'Search wp_posts for the flagged keywords and remove the spam content.',
				'Check wp_options for any injected scripts in active_plugins or theme_mods.',
				'Install a database backup plugin and restore from a clean state if needed.',
				'Update all plugins to close the injection vulnerability.',
			),
		),

		'suspicious_admin_user' => array(
			'name'        => 'Unauthorised Admin Account Detected',
			'indicators'  => array( 'suspicious_admin_user' ),
			'severity'    => 'critical',
			'explanation' => 'A new administrator account was recently created on your site. If you did not create this account, it means an attacker has gained access and is maintaining persistence by creating their own admin user. Even if you delete their uploaded files, they can log back in at any time.',
			'impact'      => array(
				'Attacker has persistent access to your site',
				'Risk of complete site takeover at any time',
				'A backdoor file may already be installed too',
			),
			'steps'       => array(
				'Go to Users and delete any accounts you did not create.',
				'Check the email address of all admin accounts for suspicious domains.',
				'Change your admin password immediately.',
				'Enable 2FA on all remaining admin accounts.',
				'Run a full malware scan - the attacker likely also uploaded a backdoor.',
			),
		),

		'php_in_uploads' => array(
			'name'        => 'PHP File Uploaded to Media Directory',
			'indicators'  => array( 'php_in_uploads' ),
			'severity'    => 'critical',
			'explanation' => 'PHP files were found in your uploads directory. Legitimate WordPress uploads (images, PDFs, documents) are never PHP files. PHP in the uploads folder means an attacker successfully uploaded a script that can execute server-side code. This is the most common hack entry point on WordPress sites.',
			'impact'      => array(
				'The PHP file can execute any server command if accessed via browser',
				'It acts as a backdoor for continued access',
				'More files can be uploaded through this entry point',
			),
			'steps'       => array(
				'Delete ALL PHP files from the uploads directory immediately.',
				'Add a rule to your .htaccess to permanently block PHP execution in uploads.',
				'Turbo Guard Firewall already blocks new PHP upload attempts going forward.',
				'Check server access logs for when the file was uploaded and from where.',
			),
		),
	);

	// -------------------------------------------------------------------------
	// PUBLIC API
	// -------------------------------------------------------------------------

	/**
	 * Analyse a completed scan and return an AI security report.
	 *
	 * @since 1.2.0
	 * @param int  $scan_id    Completed scan ID.
	 * @param bool $use_openai Whether to enhance with OpenAI API.
	 * @return array Report data.
	 */
	public static function analyse_scan( $scan_id, $use_openai = false ) {
		$results = Turbo_Guard_Scanner::get_scan_results( absint( $scan_id ) );

		if ( empty( $results ) ) {
			return self::clean_report();
		}

		// Build threat-type frequency map.
		$threat_types = array();
		$severity_max = 'info';
		foreach ( $results as $result ) {
			$threat_types[] = $result->threat_type;
			if ( self::severity_rank( $result->severity ) > self::severity_rank( $severity_max ) ) {
				$severity_max = $result->severity;
			}
		}
		$threat_types = array_unique( $threat_types );

		// Match threat types to named attack campaigns.
		$matched_campaigns   = array();
		$all_recommendations = array();

		foreach ( self::$attack_patterns as $campaign ) {
			$intersection = array_intersect( $campaign['indicators'], $threat_types );
			if ( ! empty( $intersection ) ) {
				$matched_campaigns[]  = array_merge( $campaign, array( 'matched' => array_values( $intersection ) ) );
				$all_recommendations  = array_merge( $all_recommendations, $campaign['steps'] );
			}
		}

		// Generic fallback if no named campaign matched.
		if ( empty( $matched_campaigns ) ) {
			$matched_campaigns[] = array(
				'name'        => 'Suspicious Files Detected',
				'severity'    => $severity_max,
				'explanation' => count( $results ) . ' suspicious file(s) match known malware patterns. Review each file carefully before deleting.',
				'impact'      => array( 'Potential unauthorised access', 'Risk of data theft or site defacement' ),
				'steps'       => array(
					'Review each flagged file in the scan results table.',
					'Delete files you do not recognise.',
					'Update all plugins and themes to close vulnerabilities.',
					'Change admin passwords as a precaution.',
				),
				'matched'     => array(),
			);
		}

		$summary = self::build_summary( count( $results ), $matched_campaigns, $severity_max );

		// Optional OpenAI enhancement.
		$ai_narrative = '';
		if ( $use_openai && get_option( 'turbo_guard_openai_api_key', '' ) ) {
			$ai_narrative = self::call_openai( $results, $matched_campaigns );
		}

		$report = array(
			'overall_status'  => ( 'info' === $severity_max ) ? 'warning' : $severity_max,
			'threat_count'    => count( $results ),
			'campaigns'       => $matched_campaigns,
			'recommendations' => array_unique( $all_recommendations ),
			'summary'         => $summary,
			'ai_narrative'    => $ai_narrative,
			'generated_at'    => current_time( 'mysql' ),
		);

		// Cache for 24 hours.
		set_transient( 'turbo_guard_ai_report_' . $scan_id, $report, DAY_IN_SECONDS );

		// Send advisory email.
		if ( 'yes' === get_option( 'turbo_guard_notify_on_threats', 'yes' ) ) {
			self::send_advisory_email( $report );
		}

		return $report;
	}

	/**
	 * Get cached AI report for a scan.
	 *
	 * @since 1.2.0
	 * @param int $scan_id Scan ID.
	 * @return array|false
	 */
	public static function get_cached_report( $scan_id ) {
		return get_transient( 'turbo_guard_ai_report_' . absint( $scan_id ) );
	}

	/**
	 * Get 30-day security score trend data.
	 *
	 * @since 1.2.0
	 * @return array
	 */
	public static function get_security_trend() {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Custom turbo_guard_scans table; 30-day trend read for the dashboard.
		$scans = $wpdb->get_results(
			"SELECT DATE(completed_at) AS scan_date, threats_found
			 FROM {$wpdb->prefix}turbo_guard_scans
			 WHERE status = 'completed'
			 AND completed_at > DATE_SUB(NOW(), INTERVAL 30 DAY)
			 ORDER BY completed_at ASC"
		);

		$trend = array();
		foreach ( $scans as $scan ) {
			$trend[] = array(
				'date'    => $scan->scan_date,
				'score'   => max( 0, 100 - ( (int) $scan->threats_found * 10 ) ),
				'threats' => (int) $scan->threats_found,
			);
		}
		return $trend;
	}

	// -------------------------------------------------------------------------
	// OPENAI INTEGRATION
	// -------------------------------------------------------------------------

	/**
	 * Call OpenAI API for enhanced narrative.
	 *
	 * Only sends anonymised data: threat types, severity levels, campaign names.
	 * No file content, no personal data is sent.
	 *
	 * @since 1.2.0
	 * @param array $results   Scan result rows.
	 * @param array $campaigns Matched attack campaigns.
	 * @return string AI narrative or empty string on failure.
	 */
	private static function call_openai( $results, $campaigns ) {
		$api_key = get_option( 'turbo_guard_openai_api_key', '' );
		if ( ! $api_key ) {
			return '';
		}

		$threat_summary = array();
		foreach ( array_slice( $results, 0, 10 ) as $r ) {
			$threat_summary[] = array(
				'threat'   => $r->threat_name,
				'type'     => $r->threat_type,
				'severity' => $r->severity,
			);
		}

		$campaign_names = implode( ', ', array_column( $campaigns, 'name' ) );

		$prompt = 'You are a friendly WordPress security expert writing to a non-technical site owner. '
			. 'A security scan found these threats: ' . wp_json_encode( $threat_summary ) . '. '
			. 'Attack campaigns identified: ' . $campaign_names . '. '
			. 'Write 2-3 short paragraphs: (1) what happened in plain English, '
			. '(2) what the risk is to their business, '
			. '(3) the 3 most important things to do RIGHT NOW. '
			. 'Be warm, reassuring, and specific. Avoid jargon.';

		// Use WordPress AI Client (WP 7.0+) if available.
		if ( function_exists( 'wp_ai_get_client' ) ) {
			try {
				$client = wp_ai_get_client();
				$result = $client->generate_text( $prompt, array(
					'max_tokens'  => 500,
					'temperature' => 0.3,
				) );
				if ( ! is_wp_error( $result ) && ! empty( $result ) ) {
					return sanitize_textarea_field( $result );
				}
			} catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch
				// Fall through to direct API call below.
			}
		}

		// Fallback: Direct OpenAI API (requires user-provided API key).
		$response = wp_remote_post(
			'https://api.openai.com/v1/chat/completions',
			array(
				'timeout' => 30,
				'headers' => array(
					'Authorization' => 'Bearer ' . $api_key,
					'Content-Type'  => 'application/json',
				),
				'body' => wp_json_encode( array(
					'model'       => 'gpt-4o-mini',
					'max_tokens'  => 500,
					'temperature' => 0.3,
					'messages'    => array(
						array( 'role' => 'user', 'content' => $prompt ),
					),
				) ),
			)
		);

		if ( is_wp_error( $response ) ) {
			return '';
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		return isset( $body['choices'][0]['message']['content'] )
			? sanitize_textarea_field( $body['choices'][0]['message']['content'] )
			: '';
	}

	// -------------------------------------------------------------------------
	// HELPERS
	// -------------------------------------------------------------------------

	/**
	 * Build a plain-English summary paragraph.
	 *
	 * @since 1.2.0
	 * @param int    $count     Total threats.
	 * @param array  $campaigns Matched campaigns.
	 * @param string $severity  Overall severity.
	 * @return string
	 */
	private static function build_summary( $count, $campaigns, $severity ) {
		$campaign_names = implode( ' and ', array_column( $campaigns, 'name' ) );

		if ( 'critical' === $severity ) {
			return 'Turbo Guard found ' . $count . ' critical threat(s) on your site. '
				. 'The scan identified evidence of ' . $campaign_names . '. '
				. 'Immediate action is required - your site is actively compromised. '
				. 'Follow the step-by-step instructions below to clean and secure your site. '
				. 'You do not need to be a technical expert - just follow the steps.';
		}

		if ( 'high' === $severity ) {
			return 'Turbo Guard detected ' . $count . ' high-severity threat(s) on your site. '
				. 'These appear to be related to ' . $campaign_names . '. '
				. 'While not all threats may be actively exploited yet, you should address these '
				. 'within 24 hours to prevent escalation.';
		}

		return 'Turbo Guard found ' . $count . ' suspicious file(s) on your site that need your attention. '
			. 'Review the flagged items and take the recommended actions below.';
	}

	/**
	 * Return a clean (no threats) report.
	 *
	 * @since 1.2.0
	 * @return array
	 */
	private static function clean_report() {
		return array(
			'overall_status'  => 'clean',
			'threat_count'    => 0,
			'campaigns'       => array(),
			'recommendations' => array(
				'Keep all plugins and themes updated.',
				'Enable 2FA on all admin accounts.',
				'Schedule weekly automatic scans.',
			),
			'summary'         => 'No threats detected. Your site is clean. Turbo Guard is actively protecting you.',
			'ai_narrative'    => '',
			'generated_at'    => current_time( 'mysql' ),
		);
	}

	/**
	 * Map severity label to numeric rank.
	 *
	 * @since 1.2.0
	 * @param string $severity Severity label.
	 * @return int
	 */
	private static function severity_rank( $severity ) {
		$ranks = array( 'info' => 1, 'low' => 2, 'medium' => 3, 'high' => 4, 'critical' => 5 );
		return isset( $ranks[ $severity ] ) ? $ranks[ $severity ] : 1;
	}

	/**
	 * Send AI advisory email to the admin.
	 *
	 * @since 1.2.0
	 * @param array $report AI report data.
	 */
	private static function send_advisory_email( $report ) {
		if ( 'clean' === $report['overall_status'] ) {
			return;
		}

		$email   = get_option( 'turbo_guard_notify_admin_email', get_option( 'admin_email' ) );
		$subject = '[' . get_bloginfo( 'name' ) . '] Security Alert: ' . ucfirst( $report['overall_status'] ) . ' threats found on your site';

		$body  = $report['summary'] . "\n\n";

		foreach ( $report['campaigns'] as $c ) {
			$body .= '== ' . $c['name'] . " ==\n";
			$body .= $c['explanation'] . "\n\n";
			$body .= "What to do:\n";
			foreach ( $c['steps'] as $i => $step ) {
				$body .= ( $i + 1 ) . '. ' . $step . "\n";
			}
			$body .= "\n";
		}

		if ( ! empty( $report['ai_narrative'] ) ) {
			$body .= "== AI Security Analysis ==\n" . $report['ai_narrative'] . "\n\n";
		}

		$body .= 'View full report: ' . admin_url( 'admin.php?page=turbo-guard-ai-report' );

		wp_mail( $email, $subject, $body );
	}
}
