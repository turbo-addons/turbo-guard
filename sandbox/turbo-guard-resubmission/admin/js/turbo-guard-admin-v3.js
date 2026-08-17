/**
 * Turbo Guard Admin JavaScript.
 *
 * @package TurboGuard
 * @since 1.0.0
 */

(function ($) {
	'use strict';

	var TurboGuard = {

		/**
		 * Initialize.
		 */
		init: function () {
			this.bindEvents();
			this.updateSelectionCount();
		},

		/**
		 * Bind event handlers.
		 */
		bindEvents: function () {
			// Scanner page.
			$( '#turbo-guard-start-scan' ).on( 'click', $.proxy( this.startScan, this ) );
			$( '#turbo-guard-select-all' ).on( 'change', $.proxy( this.toggleSelectAll, this ) );
			$( '#turbo-guard-select-critical' ).on( 'click', $.proxy( this.selectCritical, this ) );
			$( '#turbo-guard-delete-selected' ).on( 'click', $.proxy( this.deleteSelected, this ) );
			$( '#turbo-guard-quarantine-selected' ).on( 'click', $.proxy( this.quarantineSelected, this ) );
			$( document ).on( 'click', '.turbo-guard-delete-single', $.proxy( this.deleteSingle, this ) );
			$( document ).on( 'click', '.turbo-guard-quarantine-single', $.proxy( this.quarantineSingle, this ) );
			$( document ).on( 'click', '.turbo-guard-ignore-single', $.proxy( this.ignoreSingle, this ) );
			$( document ).on( 'click', '.turbo-guard-delete-post', $.proxy( this.deletePost, this ) );
			$( document ).on( 'change', '.turbo-guard-file-check', $.proxy( this.updateSelectionCount, this ) );

			// Settings page.
			$( '#turbo-guard-settings-form' ).on( 'submit', $.proxy( this.saveSettings, this ) );

			// Firewall: block IP from form.
			$( '#turbo-guard-block-ip-form' ).on( 'submit', $.proxy( this.blockIp, this ) );

			// Firewall: unblock IP button.
			$( document ).on( 'click', '.turbo-guard-unblock-ip', $.proxy( this.unblockIp, this ) );

			// Firewall: block from log button.
			$( document ).on(
				'click',
				'.turbo-guard-block-from-log',
				function () {
					var ip = $( this ).data( 'ip' );
					$( '#turbo-guard-block-ip-input' ).val( ip );
					$( '#turbo-guard-block-ip-form' ).trigger( 'submit' );
				}
			);
		},

		// =========================================================
		// SCANNER
		// =========================================================

		/**
		 * Start malware scan.
		 */
		startScan: function (e) {
			e.preventDefault();

			var self = this;
			var $btn = $( '#turbo-guard-start-scan' );

			$btn.prop( 'disabled', true ).html( '<span class="dashicons dashicons-update-alt" style="animation:rotation 1s infinite linear;vertical-align:middle;"></span> Scanning...' );
			$( '#turbo-guard-scan-progress' ).show();
			$( '#turbo-guard-progress-label' ).text( 'Starting scan...' );

			$.ajax(
				{
					url:  turboGuardAdmin.ajaxUrl,
					type: 'POST',
					data: {
						action: 'turbo_guard_start_scan',
						nonce:  turboGuardAdmin.nonce
					},
					success: function (response) {
						if (response.success) {
							self.continueScan( response.data.scan_id, 0 );
						} else {
							alert( 'Error: ' + (response.data ? response.data.message : 'Failed to start scan') );
							$btn.prop( 'disabled', false ).html( '<span class="dashicons dashicons-search"></span> Start Full Scan' );
							$( '#turbo-guard-scan-progress' ).hide();
						}
					},
					error: function (xhr) {
						alert( 'AJAX error starting scan. Status: ' + xhr.status );
						$btn.prop( 'disabled', false ).html( '<span class="dashicons dashicons-search"></span> Start Full Scan' );
						$( '#turbo-guard-scan-progress' ).hide();
					}
				}
			);
		},

		/**
		 * Continue scanning in chunks.
		 */
		continueScan: function (scanId, offset) {
			var self = this;

			$.ajax(
				{
					url:  turboGuardAdmin.ajaxUrl,
					type: 'POST',
					data: {
						action:  'turbo_guard_scan_chunk',
						nonce:   turboGuardAdmin.nonce,
						scan_id: scanId,
						offset:  offset
					},
					success: function (response) {
						if ( ! response.success) {
							alert( 'Scan chunk error: ' + (response.data ? response.data.message : 'Unknown') );
							location.reload();
							return;
						}

						var data = response.data;

						// Update progress bar.
						$( '#turbo-guard-progress-fill' ).css( 'width', data.percent + '%' );
						$( '#turbo-guard-progress-count' ).text( data.scanned + ' / ' + data.total + ' files' );
						$( '#turbo-guard-progress-label' ).text(
							data.percent + '% scanned' + (data.new_threats > 0 ? ' — ' + data.new_threats + ' threat(s) found' : '')
						);

						if (data.done) {
							$( '#turbo-guard-progress-label' ).text( 'Scan Complete! Reloading...' );
							setTimeout(
								function () {
									location.reload();
								},
								1200
							);
						} else {
							// Small delay to avoid hammering server.
							setTimeout(
								function () {
									self.continueScan( scanId, data.next_offset );
								},
								100
							);
						}
					},
					error: function (xhr) {
						alert( 'Scan error at offset ' + offset + '. Status: ' + xhr.status + '. The scan may have partially completed — refresh the page.' );
						location.reload();
					}
				}
			);
		},

		/**
		 * Toggle select all checkboxes.
		 */
		toggleSelectAll: function () {
			var checked = $( '#turbo-guard-select-all' ).is( ':checked' );
			$( '.turbo-guard-file-check' ).prop( 'checked', checked );
			this.updateSelectionCount();
		},

		/**
		 * Select only critical severity files.
		 */
		selectCritical: function () {
			$( '.turbo-guard-file-check' ).each(
				function () {
					$( this ).prop( 'checked', $( this ).data( 'severity' ) === 'critical' );
				}
			);
			this.updateSelectionCount();
		},

		/**
		 * Update selection count badge.
		 */
		updateSelectionCount: function () {
			var count = $( '.turbo-guard-file-check:checked' ).length;
			$( '#turbo-guard-selection-count' ).text( count + ' selected' );

			// Enable/disable bulk action buttons.
			var disabled = count === 0;
			$( '#turbo-guard-delete-selected, #turbo-guard-quarantine-selected' ).prop( 'disabled', disabled );
		},

		/**
		 * Delete selected files.
		 */
		deleteSelected: function (e) {
			e.preventDefault();

			var ids = this.getSelectedIds();
			if (ids.length === 0) {
				alert( 'Please select at least one file.' );
				return;
			}

			if ( ! window.confirm( 'Delete ' + ids.length + ' file(s)? A backup ZIP will be created automatically before deletion.' )) {
				return;
			}

			this.performAction( 'delete', ids, 'turbo_guard_delete_files' );
		},

		/**
		 * Quarantine selected files.
		 */
		quarantineSelected: function (e) {
			e.preventDefault();

			var ids = this.getSelectedIds();
			if (ids.length === 0) {
				alert( 'Please select at least one file.' );
				return;
			}

			this.performAction( 'quarantine', ids, 'turbo_guard_quarantine_files' );
		},

		/**
		 * Delete single file (row action button).
		 */
		deleteSingle: function (e) {
			e.preventDefault();
			e.stopPropagation();

			var id = $( e.currentTarget ).data( 'id' );
			if ( ! id) {
				return;
			}

			if ( ! window.confirm( 'Delete this file? A backup will be created automatically.' )) {
				return;
			}

			this.performAction( 'delete', [id], 'turbo_guard_delete_files' );
		},

		/**
		 * Quarantine single file (row action button).
		 */
		quarantineSingle: function (e) {
			e.preventDefault();
			e.stopPropagation();

			var id = $( e.currentTarget ).data( 'id' );
			if ( ! id) {
				return;
			}

			this.performAction( 'quarantine', [id], 'turbo_guard_quarantine_files' );
		},

		/**
		 * Ignore a single file — marks it as safe and excludes it from future scans.
		 *
		 * This is the same pattern as Wordfence's "Ignore" button. The file is NOT
		 * deleted; it is just added to a permanent allowlist stored in wp_options.
		 * To undo, go to Settings → Ignored Files.
		 */
		ignoreSingle: function (e) {
			e.preventDefault();
			e.stopPropagation();

			var id  = $( e.currentTarget ).data( 'id' );
			if ( ! id) {
				return;
			}

			if ( ! window.confirm( 'Mark this file as safe?\n\nIt will be excluded from all future scans. Use this only if you are certain the file is NOT malicious.' )) {
				return;
			}

			var self    = this;
			var $row    = $( '.turbo-guard-result-row[data-id="' + id + '"]' );
			var $result = $( '#turbo-guard-action-result' );
			var $btn    = $( e.currentTarget );

			$btn.prop( 'disabled', true ).text( 'Ignoring...' );

			$.ajax(
				{
					url:  turboGuardAdmin.ajaxUrl,
					type: 'POST',
					data: {
						action:    'turbo_guard_ignore_file',
						nonce:     turboGuardAdmin.nonce,
						result_id: id
					},
					success: function (response) {
						if (response.success) {
							$row.fadeOut(
								300,
								function () {
									$( this ).remove();

									// If no more rows, reload to show clean state.
									if ($( '.turbo-guard-result-row' ).length === 0) {
										location.reload();
									}
								}
							);

							$result
								.removeClass( 'notice-error' )
								.addClass( 'notice notice-success' )
								.html( '<p>&#128274; File marked as safe and excluded from future scans. <em>To undo, go to Settings &rarr; Ignored Files.</em></p>' )
								.show();

						} else {
							$result
								.removeClass( 'notice-success' )
								.addClass( 'notice notice-error' )
								.html( '<p>&#10007; ' + (response.data ? response.data.message : 'Could not ignore file.') + '</p>' )
								.show();
							$btn.prop( 'disabled', false ).html( '<span class="dashicons dashicons-hidden" style="font-size:13px;width:13px;height:13px;vertical-align:middle;margin-right:3px;"></span> Ignore' );
						}
					},
					error: function (xhr) {
						$result
							.addClass( 'notice notice-error' )
							.html( '<p>&#10007; Server error: ' + xhr.status + '</p>' )
							.show();
						$btn.prop( 'disabled', false ).html( '<span class="dashicons dashicons-hidden" style="font-size:13px;width:13px;height:13px;vertical-align:middle;margin-right:3px;"></span> Ignore' );
					}
				}
			);
		},

		/**
		 * Delete a spam post from the database (DB scan result).
		 */
		deletePost: function (e) {
			e.preventDefault();
			e.stopPropagation();

			var postId   = $( e.currentTarget ).data( 'post-id' );
			var resultId = $( e.currentTarget ).data( 'result-id' );
			if ( ! postId ) { return; }

			if ( ! window.confirm( 'Permanently delete post #' + postId + ' from the database?\n\nThis cannot be undone.' ) ) {
				return;
			}

			var self    = this;
			var $row    = $( '.turbo-guard-result-row[data-id="' + resultId + '"]' );
			var $result = $( '#turbo-guard-action-result' );
			var $btn    = $( e.currentTarget );

			$btn.prop( 'disabled', true ).text( 'Deleting...' );

			$.ajax( {
				url:  turboGuardAdmin.ajaxUrl,
				type: 'POST',
				data: {
					action:  'turbo_guard_delete_spam_post',
					nonce:   turboGuardAdmin.nonce,
					post_id: postId
				},
				success: function( response ) {
					if ( response.success ) {
						$row.fadeOut( 300, function() {
							$( this ).remove();
							if ( $( '.turbo-guard-result-row' ).length === 0 ) {
								location.reload();
							}
						} );
						$result
							.removeClass( 'notice-error' )
							.addClass( 'notice notice-success' )
							.html( '<p>&#10003; Post #' + postId + ' deleted from database.</p>' )
							.show();
					} else {
						$result
							.addClass( 'notice notice-error' )
							.html( '<p>&#10007; ' + ( response.data ? response.data.message : 'Could not delete post.' ) + '</p>' )
							.show();
						$btn.prop( 'disabled', false ).text( 'Delete Post' );
					}
				},
				error: function( xhr ) {
					$result
						.addClass( 'notice notice-error' )
						.html( '<p>&#10007; Server error: ' + xhr.status + '</p>' )
						.show();
					$btn.prop( 'disabled', false ).text( 'Delete Post' );
				}
			} );
		},

		/**
		 * Perform file delete or quarantine via AJAX.		 *
		 * Sends result_ids as result_ids[0], result_ids[1], ...
		 * so PHP receives a proper $_POST['result_ids'] array.
		 */
		performAction: function (type, ids, ajaxAction) {
			var self    = this;
			var $result = $( '#turbo-guard-action-result' );

			// Reset notice.
			$result.hide().removeClass( 'notice-success notice-error notice' ).html( '' );

			// Disable buttons during request.
			$( '#turbo-guard-delete-selected, #turbo-guard-quarantine-selected, .turbo-guard-delete-single, .turbo-guard-quarantine-single, .turbo-guard-ignore-single' ).prop( 'disabled', true );

			// Build POST data manually so arrays serialize correctly.
			var postData  = 'action=' + encodeURIComponent( ajaxAction ) + '&nonce=' + encodeURIComponent( turboGuardAdmin.nonce );
			var idsLength = ids.length;
			for (var i = 0; i < idsLength; i++) {
				postData += '&result_ids%5B%5D=' + encodeURIComponent( ids[i] );
			}

			$.ajax(
				{
					url:         turboGuardAdmin.ajaxUrl,
					type:        'POST',
					data:        postData,
					contentType: 'application/x-www-form-urlencoded; charset=UTF-8',
					success: function (response) {
						if (response.success) {
							var data = response.data;

							// Fade out and remove each handled row.
							$.each(
								ids,
								function (i, id) {
									$( '.turbo-guard-result-row[data-id="' + id + '"]' ).fadeOut(
										300,
										function () {
											$( this ).remove();
										}
									);
								}
							);

							var msg = '';
							if (type === 'delete') {
								msg = '\u2713 Deleted <strong>' + (data.deleted || ids.length) + '</strong> file(s) successfully.';
								if (data.backup) {
									msg += ' Backup ZIP saved.';
								}
								if (data.failed && data.failed > 0) {
									msg += ' <span style="color:#d63638;">' + data.failed + ' file(s) could not be deleted (check file permissions).</span>';
								}
							} else {
								msg = '\u2713 Quarantined <strong>' + ids.length + '</strong> file(s) successfully.';
							}

							$result
							.addClass( 'notice notice-success' )
							.html( '<p>' + msg + '</p>' )
							.show();

							// Uncheck select-all.
							$( '#turbo-guard-select-all' ).prop( 'checked', false );

							// Reload page if no more rows.
							setTimeout(
								function () {
									if ($( '.turbo-guard-result-row' ).length === 0) {
										location.reload();
									}
								},
								800
							);

						} else {
							var errMsg = (response.data && response.data.message) ? response.data.message : 'Action failed. Check file permissions.';
							$result
							.addClass( 'notice notice-error' )
							.html( '<p>\u2717 ' + errMsg + '</p>' )
							.show();
						}
					},
					error: function (xhr, status, errorThrown) {
						$result
						.addClass( 'notice notice-error' )
						.html( '<p>\u2717 Server error: ' + status + ' ' + errorThrown + ' (Status ' + xhr.status + ')</p>' )
						.show();
					},
					complete: function () {
						// Re-enable all action buttons.
						$( '#turbo-guard-delete-selected, #turbo-guard-quarantine-selected, .turbo-guard-delete-single, .turbo-guard-quarantine-single, .turbo-guard-ignore-single' ).prop( 'disabled', false );
						self.updateSelectionCount();
					}
				}
			);
		},

		/**
		 * Get array of checked file IDs.
		 */
		getSelectedIds: function () {
			var ids = [];
			$( '.turbo-guard-file-check:checked' ).each(
				function () {
					ids.push( $( this ).val() );
				}
			);
			return ids;
		},

		// =========================================================
		// SETTINGS
		// =========================================================

		/**
		 * Save settings form via AJAX.
		 */
		saveSettings: function (e) {
			e.preventDefault();

			var self    = this;
			var $btn    = $( '#turbo-guard-save-settings' );
			var $result = $( '#turbo-guard-settings-result' );

			$btn.prop( 'disabled', true ).text( 'Saving...' );
			$result.hide().removeClass( 'notice-success notice-error notice' ).html( '' );

			// Collect all field values.
			var settings = {};

			$( '#turbo-guard-settings-form input[type="checkbox"]' ).each(
				function () {
					settings[$( this ).attr( 'name' )] = $( this ).is( ':checked' ) ? 'yes' : 'no';
				}
			);

			$( '#turbo-guard-settings-form input[type="number"], #turbo-guard-settings-form input[type="email"], #turbo-guard-settings-form select:not([multiple])' ).each(
				function () {
					var val  = $( this ).val();
					var name = $( this ).attr( 'name' );
					if (name === 'lockout_duration') {
						val = parseInt( val, 10 ) * 60; // convert minutes to seconds.
					}
					settings[name] = val;
				}
			);

			// Textarea fields (e.g. trusted_ips).
			$( '#turbo-guard-settings-form textarea' ).each( function () {
				settings[$( this ).attr( 'name' )] = $( this ).val();
			} );

			// Build POST string with settings as settings[key]=value.
			var postData = 'action=turbo_guard_save_settings&nonce=' + encodeURIComponent( turboGuardAdmin.nonce );
			$.each(
				settings,
				function (key, val) {
					postData += '&settings%5B' + encodeURIComponent( key ) + '%5D=' + encodeURIComponent( val );
				}
			);

			// Multi-select: allowed_countries[] — send as array.
			$( '#allowed_countries option:selected' ).each( function () {
				postData += '&settings%5Ballowed_countries%5D%5B%5D=' + encodeURIComponent( $( this ).val() );
			} );

			$.ajax(
				{
					url:         turboGuardAdmin.ajaxUrl,
					type:        'POST',
					data:        postData,
					contentType: 'application/x-www-form-urlencoded; charset=UTF-8',
					success: function (response) {
						if (response.success) {
							$result
							.addClass( 'notice notice-success' )
							.html( '<p>\u2713 Settings saved successfully!</p>' )
							.show();
						} else {
							$result
							.addClass( 'notice notice-error' )
							.html( '<p>\u2717 Failed to save settings.</p>' )
							.show();
						}
						setTimeout(
							function () {
								$result.fadeOut(); },
							3000
						);
					},
					complete: function () {
						$btn.prop( 'disabled', false ).html( '<span class="dashicons dashicons-saved"></span> Save Settings' );
					}
				}
			);
		},

		// =========================================================
		// FIREWALL
		// =========================================================

		/**
		 * Block an IP address.
		 */
		blockIp: function (e) {
			e.preventDefault();

			var ip = $( '#turbo-guard-block-ip-input' ).val().trim();
			if ( ! ip) {
				alert( 'Please enter an IP address.' );
				return;
			}

			$.ajax(
				{
					url:  turboGuardAdmin.ajaxUrl,
					type: 'POST',
					data: {
						action:     'turbo_guard_block_ip',
						nonce:      turboGuardAdmin.nonce,
						ip_address: ip
					},
					success: function (response) {
						if (response.success) {
							location.reload();
						} else {
							alert( 'Error: ' + (response.data ? response.data.message : 'Could not block IP') );
						}
					}
				}
			);
		},

		/**
		 * Unblock an IP address.
		 */
		unblockIp: function (e) {
			e.preventDefault();

			var ip = $( e.currentTarget ).data( 'ip' );
			if ( ! ip) {
				return;
			}

			if ( ! window.confirm( 'Unblock IP ' + ip + '?' )) {
				return;
			}

			$.ajax(
				{
					url:  turboGuardAdmin.ajaxUrl,
					type: 'POST',
					data: {
						action:     'turbo_guard_unblock_ip',
						nonce:      turboGuardAdmin.nonce,
						ip_address: ip
					},
					success: function (response) {
						if (response.success) {
							location.reload();
						} else {
							alert( 'Error: ' + (response.data ? response.data.message : 'Could not unblock IP') );
						}
					}
				}
			);
		}
	};

	// Boot on DOM ready.
	$( document ).ready(
		function () {
			TurboGuard.init();
		}
	);

})( jQuery );


/**
 * =========================================================
 * Google Search Console (GSC) Module
 * =========================================================
 */
jQuery( function( $ ) {

var TurboGuardGSC = {

	// All fetched URLs from Google.
	allUrls: [],

	// Spam pattern categories.
	spamPatterns: {
		// Numbered folder spam (e.g., /wp-admin/images/581824/).
		numbered_folders: /\/\d{4,}\//,
		// Japanese characters.
		japanese: /[\u3040-\u309f\u30a0-\u30ff\u4e00-\u9faf]/,
		// Chinese characters.
		chinese: /[\u4e00-\u9fff\u3400-\u4dbf]/,
		// PHP in wrong locations.
		php_in_admin: /\/wp-admin\/(images|css|js)\/.+\.php$/i,
		// Random hash paths.
		hash_paths: /\/[a-f0-9]{8,}\//i,
	},

	init: function () {
		if ( $( '#turbo-guard-fetch-urls' ).length === 0 ) {
			return; // Not on GSC page.
		}
		this.bindEvents();
	},

	bindEvents: function () {
		$( '#turbo-guard-fetch-urls' ).on( 'click', $.proxy( this.fetchUrls, this ) );
		$( '#turbo-guard-gsc-select-all' ).on( 'change', $.proxy( this.toggleSelectAll, this ) );
		$( '#turbo-guard-select-spam-only' ).on( 'click', $.proxy( this.selectSpamOnly, this ) );
		$( '#turbo-guard-remove-selected' ).on( 'click', $.proxy( this.removeSelected, this ) );
		$( '#turbo-guard-generate-htaccess' ).on( 'click', $.proxy( this.generateHtaccess, this ) );
		$( '#turbo-guard-copy-htaccess' ).on( 'click', this.copyHtaccess );
		$( '#turbo-guard-filter-spam' ).on( 'change', $.proxy( this.renderTable, this ) );
		$( '#turbo-guard-gsc-disconnect' ).on( 'click', $.proxy( this.disconnect, this ) );
		$( document ).on( 'change', '.turbo-guard-gsc-check', $.proxy( this.updateSelectionCount, this ) );
	},

	/**
	 * Fetch indexed URLs from Google via AJAX.
	 */
	fetchUrls: function (e) {
		e.preventDefault();

		var self = this;
		var $btn = $( '#turbo-guard-fetch-urls' );

		$btn.prop( 'disabled', true ).text( 'Fetching...' );
		$( '#turbo-guard-gsc-loading' ).show();
		$( '#turbo-guard-gsc-results' ).hide();

		$.ajax(
			{
				url:  turboGuardAdmin.ajaxUrl,
				type: 'POST',
				data: {
					action: 'turbo_guard_gsc_get_urls',
					nonce:  turboGuardAdmin.nonce
				},
				success: function (response) {
					if (response.success) {
						self.allUrls = response.data.urls || [];
						self.renderTable();
						$( '#turbo-guard-gsc-results' ).show();
					} else {
						$( '#turbo-guard-gsc-notice' )
						.addClass( 'notice notice-error' )
						.html( '<p>Error: ' + (response.data ? response.data.message : 'Failed to fetch URLs') + '</p>' )
						.show();
					}
				},
				error: function (xhr) {
					$( '#turbo-guard-gsc-notice' )
					.addClass( 'notice notice-error' )
					.html( '<p>Server error: ' + xhr.status + '</p>' )
					.show();
				},
				complete: function () {
					$( '#turbo-guard-gsc-loading' ).hide();
					$btn.prop( 'disabled', false ).html( '<span class="dashicons dashicons-download"></span> Fetch Indexed URLs from Google' );
				}
			}
		);
	},

	/**
	 * Check if a URL is suspected spam.
	 */
	isSpam: function (url) {
		for (var key in this.spamPatterns) {
			if (this.spamPatterns[key].test( url )) {
				return key;
			}
		}
		return false;
	},

	/**
	 * Get spam type label for display.
	 */
	getSpamLabel: function (key) {
		var labels = {
			numbered_folders: 'SEO Spam (Random Folder)',
			japanese:         'Japanese Spam',
			chinese:          'Chinese Spam',
			php_in_admin:     'PHP in Admin',
			hash_paths:       'Hash Path Spam'
		};
		return labels[key] || 'Spam';
	},

	/**
	 * Render URL table.
	 */
	renderTable: function () {
		var self           = this;
		var filterSpam     = $( '#turbo-guard-filter-spam' ).is( ':checked' );
		var $tbody         = $( '#turbo-guard-url-tbody' );
		var spamCount      = 0;
		var displayedCount = 0;
		var rows           = '';

		this.allUrls.forEach(
			function (url) {
				var spamType = self.isSpam( url );
				if (spamType) {
					spamCount++;
				}

				if (filterSpam && ! spamType) {
					return;
				}

				displayedCount++;
				var badgeHtml = spamType
				? '<span class="turbo-guard-badge turbo-guard-badge-critical">' + self.getSpamLabel( spamType ) + '</span>'
				: '<span class="turbo-guard-badge turbo-guard-badge-info">Normal</span>';

				rows += '<tr class="' + (spamType ? 'turbo-guard-spam-row' : '') + '">' +
				'<td><input type="checkbox" class="turbo-guard-gsc-check" value="' + url + '" data-spam="' + (spamType || '') + '" /></td>' +
				'<td class="turbo-guard-url-cell"><a href="' + url + '" target="_blank" rel="noopener">' + url + '</a></td>' +
				'<td><span class="turbo-guard-badge turbo-guard-badge-info">Indexed</span></td>' +
				'<td>' + badgeHtml + '</td>' +
				'</tr>';
			}
		);

		$tbody.html( rows || '<tr><td colspan="4" style="text-align:center;padding:20px;">No URLs found matching filter.</td></tr>' );

		$( '#turbo-guard-url-count' ).text( this.allUrls.length );
		$( '#turbo-guard-spam-count' ).html(
			'<span style="color:#d63638;font-weight:600;">' + spamCount + ' suspected spam</span>'
		);

		this.updateSelectionCount();
	},

	/**
	 * Toggle select all.
	 */
	toggleSelectAll: function () {
		var checked = $( '#turbo-guard-gsc-select-all' ).is( ':checked' );
		$( '.turbo-guard-gsc-check:visible' ).prop( 'checked', checked );
		this.updateSelectionCount();
	},

	/**
	 * Select only spam URLs.
	 */
	selectSpamOnly: function () {
		$( '.turbo-guard-gsc-check' ).each(
			function () {
				$( this ).prop( 'checked', ! ! $( this ).data( 'spam' ) );
			}
		);
		this.updateSelectionCount();
	},

	/**
	 * Update selection count badge.
	 */
	updateSelectionCount: function () {
		var count = $( '.turbo-guard-gsc-check:checked' ).length;
		$( '#turbo-guard-gsc-selection-count' ).text( count + ' selected' );
		$( '#turbo-guard-remove-selected, #turbo-guard-generate-htaccess' ).prop( 'disabled', count === 0 );
	},

	/**
	 * Get selected URLs.
	 */
	getSelectedUrls: function () {
		var urls = [];
		$( '.turbo-guard-gsc-check:checked' ).each(
			function () {
				urls.push( $( this ).val() );
			}
		);
		return urls;
	},

	/**
	 * Submit bulk removal request to Google.
	 */
	removeSelected: function (e) {
		e.preventDefault();

		var urls = this.getSelectedUrls();
		if (urls.length === 0) {
			alert( 'Select at least one URL.' ); return; }

		if ( ! window.confirm( 'Request removal of ' + urls.length + ' URLs from Google index?\n\nNote: Removal takes 24-72 hours to process.' )) {
			return;
		}

		var self    = this;
		var $btn    = $( '#turbo-guard-remove-selected' );
		var $notice = $( '#turbo-guard-gsc-notice' );

		$btn.prop( 'disabled', true ).text( 'Submitting...' );
		$notice.hide().removeClass( 'notice-success notice-error notice' );

		// Build POST data with urls array.
		var postData = 'action=turbo_guard_gsc_remove_urls&nonce=' + encodeURIComponent( turboGuardAdmin.nonce );
		urls.forEach(
			function (url, i) {
				postData += '&urls%5B%5D=' + encodeURIComponent( url );
			}
		);

		$.ajax(
			{
				url:         turboGuardAdmin.ajaxUrl,
				type:        'POST',
				data:        postData,
				contentType: 'application/x-www-form-urlencoded; charset=UTF-8',
				success: function (response) {
					if (response.success) {
						var data = response.data;

						// Remove successfully submitted rows.
						$( '.turbo-guard-gsc-check:checked' ).each(
							function () {
								$( this ).closest( 'tr' ).fadeOut(
									300,
									function () {
										$( this ).remove(); }
								);
							}
						);

						$notice
							.addClass( 'notice notice-success' )
							.html(
								'<p>&#10003; Removal requested for <strong>' + (data.submitted || urls.length) + '</strong> URLs. ' +
								'Google will process removals within 24-72 hours. ' +
								(data.failed ? '<span style="color:#d63638;">' + data.failed + ' failed.</span>' : '') + '</p>'
							)
							.show();

						// Also submit sitemap reindex.
						self.resubmitSitemap();

					} else {
						$notice
						.addClass( 'notice notice-error' )
						.html( '<p>&#10007; ' + (response.data ? response.data.message : 'Failed to submit removal requests') + '</p>' )
						.show();
					}
				},
				error: function (xhr) {
					$notice
					.addClass( 'notice notice-error' )
					.html( '<p>&#10007; Server error: ' + xhr.status + '</p>' )
					.show();
				},
				complete: function () {
					$btn.prop( 'disabled', false ).html( '<span class="dashicons dashicons-trash"></span> Request Removal from Google' );
					self.updateSelectionCount();
				}
			}
		);
	},

	/**
	 * Generate .htaccess redirect rules.
	 */
	generateHtaccess: function (e) {
		e.preventDefault();

		var urls = this.getSelectedUrls();
		if (urls.length === 0) {
			alert( 'Select at least one URL.' ); return; }

		var siteUrl = window.location.origin;
		var rules   = '# Turbo Guard - SEO Spam URL Redirects\n';
		rules      += '# Generated: ' + new Date().toISOString() + '\n';
		rules      += '# Redirects spam/malware URLs to homepage to prevent 404 errors\n\n';
		rules      += '<IfModule mod_rewrite.c>\n';
		rules      += 'RewriteEngine On\n\n';

		// Build unique path prefixes to avoid massive rule sets.
		var paths = {};
		urls.forEach(
			function (url) {
				try {
					var parsed = new URL( url );
					var path   = parsed.pathname;

					// Get first 2-3 path segments.
					var parts = path.split( '/' ).filter( Boolean );
					if (parts.length > 1) {
						var prefix    = '/' + parts.slice( 0, 2 ).join( '/' ) + '/';
						paths[prefix] = true;
					} else {
						paths[path] = true;
					}
				} catch (err) {
				}
			}
		);

		Object.keys( paths ).forEach(
			function (path) {
				rules += '# Redirect: ' + path + '\n';
				rules += 'RewriteRule ^' + path.replace( /\//g, '\\/' ).replace( /\./g, '\\.' ) + '.*$ ' + siteUrl + '/ [R=301,L]\n\n';
			}
		);

		rules += '</IfModule>\n';
		rules += '# End Turbo Guard redirects\n';

		$( '#turbo-guard-htaccess-code' ).val( rules );
		$( '#turbo-guard-htaccess-preview' ).show();

		// Scroll to preview.
		$( 'html,body' ).animate( { scrollTop: $( '#turbo-guard-htaccess-preview' ).offset().top - 50 }, 400 );
	},

	/**
	 * Copy htaccess code to clipboard.
	 */
	copyHtaccess: function () {
		var $textarea = $( '#turbo-guard-htaccess-code' );
		$textarea[0].select();
		document.execCommand( 'copy' );
		$( '#turbo-guard-copy-htaccess' ).text( 'Copied!' );
		setTimeout(
			function () {
				$( '#turbo-guard-copy-htaccess' ).html( '<span class="dashicons dashicons-clipboard"></span> Copy to Clipboard' );
			},
			2000
		);
	},

	/**
	 * Resubmit sitemap after cleanup.
	 */
	resubmitSitemap: function () {
		$.post(
			turboGuardAdmin.ajaxUrl,
			{
				action: 'turbo_guard_gsc_submit_sitemap',
				nonce:  turboGuardAdmin.nonce
			},
			function (response) {
				if (response.success) {
					$( '#turbo-guard-gsc-notice' ).append( ' Sitemap resubmitted to Google. &#10003;' );
				}
			}
		);
	},

	/**
	 * Disconnect GSC.
	 */
	disconnect: function (e) {
		e.preventDefault();
		if ( ! window.confirm( 'Disconnect Google Search Console? You will need to reconnect to use this feature.' )) {
			return;
		}
		$.post(
			turboGuardAdmin.ajaxUrl,
			{
				action: 'turbo_guard_gsc_disconnect',
				nonce:  turboGuardAdmin.nonce
			},
			function () {
				location.reload();
			}
		);
	}
};

// Initialize GSC module — wrapped inside jQuery IIFE above.
TurboGuardGSC.init();

} ); // end jQuery GSC wrapper


/**
 * GSC Setup: Copy redirect URI button.
 */
jQuery( document ).ready( function( $ ) {
	$( document ).on( 'click', '.turbo-guard-copy-redirect-uri', function() {
		var uri = $( this ).data( 'uri' );
		if ( navigator.clipboard ) {
			navigator.clipboard.writeText( uri );
		} else {
			// Fallback.
			var $tmp = $( '<input>' );
			$( 'body' ).append( $tmp );
			$tmp.val( uri ).select();
			document.execCommand( 'copy' );
			$tmp.remove();
		}
		var $btn = $( this );
		$btn.text( 'Copied!' );
		setTimeout( function() { $btn.text( 'Copy' ); }, 2000 );
	} );
} );


/**
 * =========================================================
 * Vulnerability Scanner Page
 * =========================================================
 */

jQuery( document ).ready( function( $ ) {
	$( '#turbo-guard-run-vuln-scan' ).on( 'click', function(e) {
		e.preventDefault();

		var $btn     = $( this );
		var $loading = $( '#turbo-guard-vuln-scanning' );
		var $notice  = $( '#turbo-guard-vuln-notice' );

		$btn.prop( 'disabled', true );
		$loading.show();
		$notice.hide().removeClass( 'notice-success notice-error notice' );

		$.ajax( {
			url:     turboGuardAdmin.ajaxUrl,
			type:    'POST',
			timeout: 120000, // 2 minutes for large sites.
			data: {
				action: 'turbo_guard_run_vuln_scan',
				nonce:  turboGuardAdmin.nonce
			},
			success: function( response ) {
				if ( response.success ) {
					$notice
						.addClass( 'notice notice-success' )
						.html( '<p>\u2713 ' + response.data.message + ' <a href="' + window.location.href + '">Refresh to see results</a></p>' )
						.show();

					// Auto-reload after 2 seconds to show updated results.
					setTimeout( function() { location.reload(); }, 2000 );
				} else {
					$notice
						.addClass( 'notice notice-error' )
						.html( '<p>\u2717 ' + ( response.data ? response.data.message : 'Scan failed.' ) + '</p>' )
						.show();
				}
			},
			error: function( xhr ) {
				$notice
					.addClass( 'notice notice-error' )
					.html( '<p>\u2717 Request error: ' + xhr.status + '. The scan may still be running — refresh the page in a moment.</p>' )
					.show();
			},
			complete: function() {
				$btn.prop( 'disabled', false );
				$loading.hide();
			}
		} );
	} );
} );


/**
 * =========================================================
 * Geo-Fence Settings Helpers
 * =========================================================
 */

jQuery( document ).ready( function( $ ) {

	// "Add My Current IP" button.
	$( '#turbo-guard-add-my-ip' ).on( 'click', function () {
		var $btn    = $( this );
		var $result = $( '#turbo-guard-my-ip-result' );

		$btn.prop( 'disabled', true ).text( 'Detecting...' );
		$result.text( '' );

		$.post(
			turboGuardAdmin.ajaxUrl,
			{
				action: 'turbo_guard_save_my_ip',
				nonce:  turboGuardAdmin.nonce
			},
			function ( response ) {
				if ( response.success ) {
					var ip       = response.data.ip;
					var $textarea = $( '#trusted_ips' );
					var current  = $textarea.val().trim();

					// Append IP if not already present.
					if ( current.indexOf( ip ) === -1 ) {
						$textarea.val( current ? current + '\n' + ip : ip );
					}

					$result.text( '\u2713 ' + ip + ' added.' ).css( 'color', '#00a32a' );
				} else {
					$result.text( '\u2717 ' + ( response.data ? response.data.message : 'Failed.' ) ).css( 'color', '#d63638' );
				}
			}
		).always( function () {
			$btn.prop( 'disabled', false ).text( '+ Add My Current IP' );
		} );
	} );

	// "Detect My Country" button.
	$( '#turbo-guard-detect-country' ).on( 'click', function () {
		var $btn    = $( this );
		var $result = $( '#turbo-guard-my-country-result' );

		$btn.prop( 'disabled', true ).text( 'Detecting...' );
		$result.text( '' );

		$.post(
			turboGuardAdmin.ajaxUrl,
			{
				action: 'turbo_guard_get_my_country',
				nonce:  turboGuardAdmin.nonce
			},
			function ( response ) {
				if ( response.success ) {
					var code = response.data.country_code;
					var name = response.data.country_name;

					// Auto-select the detected country in the multi-select.
					$( '#allowed_countries option[value="' + code + '"]' ).prop( 'selected', true );

					$result.text( '\u2713 ' + name + ' (' + code + ') selected.' ).css( 'color', '#00a32a' );
				} else {
					$result.text( '\u2717 Could not detect country.' ).css( 'color', '#d63638' );
				}
			}
		).always( function () {
			$btn.prop( 'disabled', false ).text( 'Detect My Country' );
		} );
	} );

} );


/**
 * =========================================================
 * Remote Notices Module — v1.3.0
 * Handles dismissal of remote notification banners fetched
 * from the Turbo Addons notification server.
 * =========================================================
 */
( function ( $ ) {
	'use strict';

	var TurboGuardNotices = {

		init: function () {
			this.bindEvents();
		},

		bindEvents: function () {
			// Dismiss button click — works for any notice rendered now or later.
			$( document ).on( 'click', '.tg-notice-dismiss', $.proxy( this.dismiss, this ) );

			// Flush notices cache button (on Settings page).
			$( document ).on( 'click', '#turbo-guard-flush-notices', $.proxy( this.flushCache, this ) );
		},

		/**
		 * Flush notification cache via AJAX.
		 */
		flushCache: function( e ) {
			e.preventDefault();

			var $btn    = $( '#turbo-guard-flush-notices' );
			var $result = $( '#turbo-guard-flush-result' );

			$btn.prop( 'disabled', true ).text( '🔄 Refreshing...' );
			$result.text( '' ).css( 'color', '' );

			$.post( turboGuardAdmin.ajaxUrl, {
				action: 'turbo_guard_flush_notices',
				nonce:  turboGuardAdmin.flushNonce,
			}, function( response ) {
				if ( response.success ) {
					$result.text( '✅ ' + response.data.message ).css( 'color', '#16a34a' );
					// Reload page after 1.5s so new notices appear.
					setTimeout( function() { location.reload(); }, 1500 );
				} else {
					$result.text( '❌ Failed.' ).css( 'color', '#dc2626' );
					$btn.prop( 'disabled', false ).text( '🔄 Refresh Notifications Now' );
				}
			} ).fail( function() {
				$result.text( '❌ Server error.' ).css( 'color', '#dc2626' );
				$btn.prop( 'disabled', false ).text( '🔄 Refresh Notifications Now' );
			} );
		},

		/**
		 * Send dismiss AJAX request, then slide-remove the banner.
		 */
		dismiss: function ( e ) {
			e.preventDefault();

			var $btn      = $( e.currentTarget );
			var noticeId  = $btn.data( 'notice-id' );
			var nonce     = $btn.data( 'nonce' );
			var $notice   = $( '#tg-notice-' + noticeId );

			if ( ! noticeId || ! nonce ) {
				// No ID or nonce — just hide visually.
				$notice.slideUp( 200 );
				return;
			}

			// Optimistic UI: hide immediately so it feels instant.
			$notice.slideUp( 180 );

			$.ajax( {
				url:  turboGuardAdmin.ajaxUrl,
				type: 'POST',
				data: {
					action:    'turbo_guard_dismiss_notice',
					notice_id: noticeId,
					nonce:     nonce
				},
				error: function () {
					// Silent failure — notice is already hidden visually.
				}
			} );
		}
	};

	$( document ).ready( function () {
		TurboGuardNotices.init();
	} );

} )( jQuery );


/**
 * =========================================================
 * AI Security Advisor — Security Score Trend Chart
 * =========================================================
 */

jQuery( function( $ ) {
	var canvas = document.getElementById( 'turbo-guard-trend-chart' );
	if ( ! canvas ) {
		return; // Not on the AI report page, or no trend canvas rendered.
	}

	var data = ( typeof turboGuardAdmin !== 'undefined' && turboGuardAdmin.trend ) ? turboGuardAdmin.trend : [];
	if ( data.length < 2 ) {
		return;
	}

	var ctx = canvas.getContext( '2d' );
	var W = canvas.offsetWidth;
	canvas.width = W;
	var H = 80;
	var scores = data.map( function( d ) { return d.score; } );
	var minS = Math.min.apply( null, scores );
	var maxS = Math.max.apply( null, scores ) || 100;
	var step = W / Math.max( data.length - 1, 1 );

	ctx.fillStyle = '#f9fafb';
	ctx.fillRect( 0, 0, W, H );

	// Draw grid lines.
	ctx.strokeStyle = '#e5e7eb';
	ctx.lineWidth = 1;
	[ 0, 25, 50, 75, 100 ].forEach( function( pct ) {
		var y = H - ( pct / 100 ) * H;
		ctx.beginPath(); ctx.moveTo( 0, y ); ctx.lineTo( W, y ); ctx.stroke();
	} );

	// Draw gradient fill.
	var gradient = ctx.createLinearGradient( 0, 0, 0, H );
	gradient.addColorStop( 0, 'rgba(37,99,235,.3)' );
	gradient.addColorStop( 1, 'rgba(37,99,235,.02)' );

	ctx.beginPath();
	data.forEach( function( d, i ) {
		var x = i * step;
		var y = H - ( ( d.score - minS ) / ( maxS - minS + 1 ) ) * ( H - 10 ) - 5;
		i === 0 ? ctx.moveTo( x, y ) : ctx.lineTo( x, y );
	} );
	ctx.lineTo( ( data.length - 1 ) * step, H );
	ctx.lineTo( 0, H );
	ctx.closePath();
	ctx.fillStyle = gradient;
	ctx.fill();

	// Draw line.
	ctx.beginPath();
	ctx.strokeStyle = '#2563eb';
	ctx.lineWidth = 2;
	data.forEach( function( d, i ) {
		var x = i * step;
		var y = H - ( ( d.score - minS ) / ( maxS - minS + 1 ) ) * ( H - 10 ) - 5;
		i === 0 ? ctx.moveTo( x, y ) : ctx.lineTo( x, y );
	} );
	ctx.stroke();
} );


/**
 * =========================================================
 * Live Traffic — Refresh + Block IP
 * =========================================================
 */

jQuery( document ).ready( function( $ ) {
	$( '#turbo-guard-refresh-traffic' ).on( 'click', function() {
		location.reload();
	} );

	$( document ).on( 'click', '.turbo-guard-block-traffic-ip', function() {
		var ip      = $( this ).data( 'ip' );
		var nonce   = $( this ).data( 'nonce' );
		var strings = turboGuardAdmin.strings || {};

		if ( ! ip || ! window.confirm( ( strings.blockIpConfirm || 'Block IP %s?' ).replace( '%s', ip ) ) ) {
			return;
		}

		var $btn = $( this ).prop( 'disabled', true ).text( strings.blocking || 'Blocking...' );
		$.post(
			turboGuardAdmin.ajaxUrl,
			{ action: 'turbo_guard_block_ip', nonce: nonce, ip_address: ip },
			function( r ) {
				if ( r.success ) {
					$btn.text( strings.blocked || 'Blocked' ).css( 'color', '#16a34a' );
				} else {
					$btn.prop( 'disabled', false ).text( strings.block || 'Block' );
					alert( r.data ? r.data.message : 'Error' );
				}
			}
		);
	} );
} );


/**
 * =========================================================
 * SEO Spam Detector — Scan + Delete
 * =========================================================
 */

jQuery( document ).ready( function( $ ) {
	var strings = turboGuardAdmin.strings || {};

	$( '#turbo-guard-run-seo-scan' ).on( 'click', function() {
		var $btn     = $( this ).prop( 'disabled', true );
		var $loading = $( '#turbo-guard-seo-scanning' );
		var $notice  = $( '#turbo-guard-seo-notice' );
		$loading.show();
		$notice.hide().removeClass( 'notice-success notice-error notice' );
		$.ajax( {
			url: turboGuardAdmin.ajaxUrl, type: 'POST', timeout: 60000,
			data: { action: 'turbo_guard_run_seo_spam_scan', nonce: turboGuardAdmin.nonce },
			success: function( r ) {
				if ( r.success ) {
					var msg = r.data.total > 0
						? '&#9888; ' + r.data.total + ' ' + ( strings.seoSpamFound || 'spam indicator(s) found.' )
						: '&#10003; ' + ( strings.noSeoSpamFound || 'No SEO spam found.' );
					$notice
						.addClass( 'notice notice-' + ( r.data.total > 0 ? 'error' : 'success' ) )
						.html( '<p>' + msg + '</p>' )
						.show();
					setTimeout( function() { location.reload(); }, 1500 );
				} else {
					$notice
						.addClass( 'notice notice-error' )
						.html( '<p>&#10007; ' + ( r.data ? r.data.message : ( strings.seoScanFailed || 'Scan failed.' ) ) + '</p>' )
						.show();
				}
			},
			error: function( xhr ) {
				$notice
					.addClass( 'notice notice-error' )
					.html( '<p>&#10007; Server error: ' + xhr.status + '</p>' )
					.show();
			},
			complete: function() { $btn.prop( 'disabled', false ); $loading.hide(); }
		} );
	} );

	$( document ).on( 'click', '.turbo-guard-delete-spam-post', function() {
		if ( ! window.confirm( strings.confirmDeleteSpamPost || 'Permanently delete this spam post?' ) ) {
			return;
		}
		var $btn  = $( this ).prop( 'disabled', true ).text( strings.deleting || 'Deleting...' );
		var id    = $( this ).data( 'id' );
		var nonce = $( this ).data( 'nonce' );
		$.post(
			turboGuardAdmin.ajaxUrl,
			{ action: 'turbo_guard_delete_spam_post', nonce: nonce, post_id: id },
			function( r ) {
				if ( r.success ) {
					$btn.closest( 'tr' ).fadeOut( 300, function() { $( this ).remove(); } );
				} else {
					$btn.prop( 'disabled', false ).text( strings.deleteFree || 'Delete (Free)' );
				}
			}
		);
	} );

	$( '#turbo-guard-delete-all-spam-posts' ).on( 'click', function() {
		var ids = $( this ).data( 'ids' ).toString().split( ',' );
		if ( ! window.confirm( strings.confirmDeleteAllSpamPosts || 'Delete all spam posts? This cannot be undone.' ) ) {
			return;
		}
		var $btn = $( this ).prop( 'disabled', true );
		var done = 0;
		ids.forEach( function( id ) {
			$.post(
				turboGuardAdmin.ajaxUrl,
				{ action: 'turbo_guard_delete_spam_post', nonce: turboGuardAdmin.nonce, post_id: parseInt( id, 10 ) },
				function() {
					done++;
					if ( done === ids.length ) {
						location.reload();
					}
				}
			);
		} );
	} );
} );


/**
 * =========================================================
 * Malware Scanner — Quick Delete Critical Files
 * =========================================================
 */

jQuery( document ).ready( function( $ ) {
	$( '#turbo-guard-quick-delete-critical' ).on( 'click', function() {
		$( '#turbo-guard-select-critical' ).trigger( 'click' );
		$( 'html,body' ).animate( { scrollTop: $( '#turbo-guard-delete-selected' ).offset().top - 100 }, 400 );
		$( '#turbo-guard-delete-selected' ).trigger( 'click' );
	} );
} );


/**
 * =========================================================
 * File Integrity — Checks, Watcher, Baseline
 * =========================================================
 */

jQuery( function( $ ) {
	var strings = turboGuardAdmin.strings || {};

	function showNotice( msg, type ) {
		$( '#turbo-guard-integrity-notice' )
			.removeClass( 'notice-success notice-error notice-warning notice' )
			.addClass( 'notice notice-' + type )
			.html( '<p>' + msg + '</p>' )
			.show();
	}

	$( '#tg-run-integrity' ).on( 'click', function() {
		var $btn = $( this ).prop( 'disabled', true ).text( strings.checking || 'Checking...' );
		$.post(
			turboGuardAdmin.ajaxUrl,
			{ action: 'turbo_guard_run_integrity_check', nonce: turboGuardAdmin.nonce },
			function( r ) {
				if ( r.success ) {
					showNotice( '\u2713 ' + r.data.message, r.data.modified + r.data.missing > 0 ? 'error' : 'success' );
					setTimeout( function() { location.reload(); }, 1500 );
				} else {
					showNotice( '\u2717 ' + ( r.data ? r.data.message : 'Failed.' ), 'error' );
				}
			}
		).always( function() { $btn.prop( 'disabled', false ).text( strings.runCheckNow || 'Run Check Now' ); } );
	} );

	$( '#tg-run-watcher' ).on( 'click', function() {
		var $btn = $( this ).prop( 'disabled', true ).text( strings.scanning || 'Scanning...' );
		$.post(
			turboGuardAdmin.ajaxUrl,
			{ action: 'turbo_guard_run_file_watcher', nonce: turboGuardAdmin.nonce },
			function( r ) {
				if ( r.success ) {
					showNotice( '\u2713 ' + r.data.message, r.data.new > 0 ? 'error' : 'success' );
					setTimeout( function() { location.reload(); }, 1500 );
				} else {
					showNotice( '\u2717 ' + ( r.data ? r.data.message : 'Failed.' ), 'error' );
				}
			}
		).always( function() { $btn.prop( 'disabled', false ).text( strings.runNow || 'Run Now' ); } );
	} );

	$( '#tg-rebuild-baseline' ).on( 'click', function() {
		if ( ! window.confirm( strings.confirmRebuildBaseline || 'Rebuild baseline? This marks all current files as trusted. Only do this on a clean site.' ) ) {
			return;
		}
		var $btn = $( this ).prop( 'disabled', true ).text( strings.building || 'Building...' );
		$.post(
			turboGuardAdmin.ajaxUrl,
			{ action: 'turbo_guard_rebuild_baseline', nonce: turboGuardAdmin.nonce },
			function( r ) {
				if ( r.success ) {
					showNotice( '\u2713 ' + r.data.message, 'success' );
					setTimeout( function() { location.reload(); }, 1500 );
				} else {
					showNotice( '\u2717 ' + ( r.data ? r.data.message : 'Failed.' ), 'error' );
				}
			}
		).always( function() { $btn.prop( 'disabled', false ).text( strings.rebuildBaseline || 'Rebuild Baseline' ); } );
	} );
} );
