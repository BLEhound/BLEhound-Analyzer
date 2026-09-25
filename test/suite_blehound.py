#
# BLEhound Analyzer tests
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''libblehound unit tests'''

import subprocess


class TestBlehound:
    def test_unit_libblehound(self, program, base_env):
        '''libblehound protocol library'''
        subprocess.check_call(program('blehound_test'), env=base_env)
