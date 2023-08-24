PORTNAME=       ${CATEGORIES:[1]}-update
PORTVERSION=    23.7.2
CATEGORIES=     sysutils

MAINTAINER=     franco@opnsense.org
COMMENT=        OPNsense update utilities
WWW=            https://opnsense.org/

LICENSE=        BSD2CLAUSE

LIB_DEPENDS+=   libucl.so:textproc/libucl

USES=           ssl

MAKE_ENV=       UPDATE_RELEASE=${PORTVERSION}

USE_GITHUB=     yes
GH_ACCOUNT=     biptec
GH_TAGNAME=     23.7

.include <bsd.port.mk>
