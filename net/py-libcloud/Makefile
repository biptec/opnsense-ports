PORTNAME=	libcloud
PORTVERSION=	3.9.1
CATEGORIES=	net python
MASTER_SITES=	PYPI
PKGNAMEPREFIX=	${PYTHON_PKGNAMEPREFIX}
DISTNAME=	apache_libcloud-${PORTVERSION}

MAINTAINER=	novel@FreeBSD.org
COMMENT=	Standard client library for many popular cloud providers
WWW=		https://libcloud.apache.org/

LICENSE=	APACHE20
LICENSE_FILE=	${WRKSRC}/LICENSE

BUILD_DEPENDS=	${PYTHON_PKGNAMEPREFIX}setuptools>=63.1.0<80.11:devel/py-setuptools@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}wheel>=0.45.1:devel/py-wheel@${PY_FLAVOR}
RUN_DEPENDS=	${PYTHON_PKGNAMEPREFIX}requests>=2.26.0:www/py-requests@${PY_FLAVOR}

NO_ARCH=	yes

USES=		cpe python
USE_PYTHON=	autoplist concurrent pep517
PYDISTUTILS_PKGNAME=	apache_libcloud
CPE_VENDOR=	apache

post-extract:
	@${MV} ${WRKSRC}/libcloud/test ${WRKSRC}/test # no need to install tests

.include <bsd.port.mk>
