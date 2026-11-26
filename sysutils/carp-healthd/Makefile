PORTNAME=	carp-healthd
DISTVERSION=	0.1.0
PORTREVISION=	1
CATEGORIES=	sysutils

MAINTAINER=	ports@FreeBSD.org
COMMENT=	Event-driven CARP health controller for OPNsense
WWW=		https://github.com/biptec/core-router-infra/issues/232

LICENSE=	BSD2CLAUSE

ONLY_FOR_ARCHS=	amd64 arm64

USES=		go:1.25+
CGO_ENABLED=	0
USE_GITHUB=	nodefault
GH_TUPLE=	golang:net:v0.55.0:golang_net/vendor/golang.org/x/net \
		golang:sys:v0.45.0:golang_sys/vendor/golang.org/x/sys

WRKSRC=		${WRKDIR}/${PORTNAME}
GO_PKGNAME=	github.com/biptec/${PORTNAME}
GO_TARGET=	${GO_PKGNAME}:${PREFIX}/sbin/${PORTNAME}
GO_LDFLAGS=	-X main.version=${DISTVERSION}

PLIST_FILES=	sbin/${PORTNAME}

_USES_extract+=	650:carp-healthd-source
carp-healthd-source:
	@${MKDIR} ${WRKSRC}
	@(cd ${FILESDIR}/src && ${COPYTREE_SHARE} . ${WRKSRC})

.include <bsd.port.mk>
