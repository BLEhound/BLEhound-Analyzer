/** @file
 *
 * Declarations of routines to manage the global list of interfaces and to
 * update widgets/windows displaying items from those lists
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __IFACE_LISTS_H__
#define __IFACE_LISTS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef HAVE_LIBPCAP
/*
 * Get the global interface list.  Generate it if we haven't
 * done so already.
 */
extern void fill_in_local_interfaces(void(*update_cb)(void));

/*
 * Get the global interface list.  Generate it if we haven't
 * done so already.
 * @param allowed_types only fill in types provided by the list
 */
extern void fill_in_local_interfaces_filtered(GList * allowed_types, void(*update_cb)(void));

/*
 * Update the global interface list.
 */
extern void scan_local_interfaces(void (*update_cb)(void));

/*
 * Update the global interface list.
 * @param allowed_types only fill in types provided by the list
 */
extern void scan_local_interfaces_filtered(GList * allowed_types, void (*update_cb)(void));

/**
 * Callback run at the end of every interface scan, so the GUI can append
 * interfaces that neither dumpcap nor extcap discover (e.g. BLEhound
 * dongles served over a local socket).
 */
typedef void (*extra_interfaces_fn)(void);

/** Set (or clear with NULL) the extra interfaces callback. */
extern void set_extra_interfaces_fn(extra_interfaces_fn fn);

/*
 * Hide the interfaces
 */
extern void hide_interface(char* new_hide);

/*
 * Update the global interface list from preferences.
 */
extern void update_local_interfaces(void);

#endif /* HAVE_LIBPCAP */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __IFACE_LISTS_H__ */
