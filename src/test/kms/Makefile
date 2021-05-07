#-------------------------------------------------------------------------
#
# Makefile for src/test/kms
#
# Portions Copyright (c) 1996-2020, PostgreSQL Global Development Group
#
# src/test/kms/Makefile
#
#-------------------------------------------------------------------------

subdir = src/test/kms
top_builddir = ../../..
include $(top_builddir)/src/Makefile.global

EXTRA_INSTALL = contrib/pgcrypto

export with_openssl

check:
	$(prove_check)

installcheck:
	$(prove_installcheck)

clean distclean maintainer-clean:
	rm -rf tmp_check
