/** @file
 *
 * BLEhound Analyzer product branding.
 *
 * BLEhound Analyzer runs the Wireshark packet flavor unchanged and layers
 * its own name and personal configuration directory on top of it, so the
 * packet analysis code paths stay identical to upstream.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#ifdef BLEHOUND_BRANDING

#define BLEHOUND_NAME_PROPER    "BLEhound Analyzer"
#define BLEHOUND_NAME_LOWER     "blehound-analyzer"
#define BLEHOUND_TAGLINE        "Bluetooth LE Protocol Analyzer"
#define BLEHOUND_DESKTOP_ID     "io.github.blehound.Analyzer"

#endif /* BLEHOUND_BRANDING */
