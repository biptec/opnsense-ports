PORTNAME=	update
PORTVERSION=	26.7
PORTREVISION=	1
CATEGORIES=	sysutils
PKGNAMEPREFIX=	opnsense-

MAINTAINER=	franco@opnsense.org
COMMENT=	OPNsense update utilities
WWW=		https://github.com/biptec/opnsense-update

LICENSE=	BSD2CLAUSE

LIB_DEPENDS+=	libucl.so:textproc/libucl

USES=		ssl

MAKE_ENV=	UPDATE_RELEASE=${PORTVERSION} UPDATE_FREEBSD=${OSREL}

USE_GITHUB=	yes
GH_ACCOUNT=	biptec
GH_PROJECT=	opnsense-update
GH_TAGNAME=	1460fe3f3aa962dfd948d44dbcfffd6528fa4532

.include <bsd.port.mk>
