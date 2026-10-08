#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Mono Technologies Inc.
#
# apk post-deinstall hook for the VPN plugin: the user its service added for
# itself goes with it. The verso group is the shell package's.
sed -i '/^verso-plugin-vpn:/d' /etc/passwd
exit 0
