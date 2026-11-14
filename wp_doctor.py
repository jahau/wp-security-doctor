#!/usr/bin/env python3
"""Backwards-compatible entry point: ``python wp_doctor.py /path/to/wordpress``.

Equivalent to ``wp-security-doctor scan /path/to/wordpress``. All options of the
``scan`` command are accepted.
"""

from wp_security_doctor.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
