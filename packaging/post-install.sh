#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Mono Technologies Inc.
#
# apk post-install / post-upgrade hook for the VPN plugin. The shell package
# owns the verso user and group; this one brings its own service up, then has
# the shell re-read the manifests (SIGHUP) so its page and nav row appear.
#
# On that rescan the shell gives every signed-in session the grant this package
# ships, as signing in would, so nobody signs in again.
/etc/init.d/verso-plugin-vpn enable 2>/dev/null
/etc/init.d/verso-plugin-vpn restart 2>/dev/null
ubus call service signal '{"name":"verso","signal":1}' 2>/dev/null
exit 0
