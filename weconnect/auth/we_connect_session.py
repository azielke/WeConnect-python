import json
import logging

from oauthlib.common import to_unicode

from requests.models import CaseInsensitiveDict
from weconnect.auth.openid_session import AccessType

from weconnect.auth.vw_web_session import VWWebSession
from weconnect.errors import TemporaryAuthentificationError


LOG = logging.getLogger("weconnect")


class WeConnectSession(VWWebSession):
    def __init__(self, sessionuser, **kwargs):
        super(WeConnectSession, self).__init__(client_id='a24fba63-34b3-4d43-b181-942111e6bda8@apps_vw-dilab_com',
                                               refresh_url='https://identity.vwgroup.io/oidc/v1/token',
                                               scope='openid profile badge cars dealers vin offline_access',
                                               redirect_uri='weconnect://authenticated',
                                               state=None,
                                               sessionuser=sessionuser,
                                               **kwargs)

        self.headers = CaseInsensitiveDict({
            'accept': '*/*',
            'content-type': 'application/json',
            'content-version': '1',
            'x-newrelic-id': 'VgAEWV9QDRAEXFlRAAYPUA==',
            'user-agent': 'Volkswagen/3.61.0-android/14',
            'accept-language': 'de-de',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'x-android-package-name': 'com.volkswagen.weconnect'
        })

    def request(
        self,
        method,
        url,
        data=None,
        headers=None,
        withhold_token=False,
        access_type=AccessType.ACCESS,
        token=None,
        timeout=None,
        **kwargs
    ):
        """Intercept all requests and add weconnect-trace-id header."""

        import secrets
        traceId = secrets.token_hex(16)
        weConnectTraceId = (traceId[:8] + '-' + traceId[8:12] + '-' + traceId[12:16] + '-' + traceId[16:20] + '-' + traceId[20:]).upper()
        headers = headers or {}
        headers['weconnect-trace-id'] = weConnectTraceId

        return super(WeConnectSession, self).request(
            method, url, headers=headers, data=data, withhold_token=withhold_token, access_type=access_type, token=token, timeout=timeout, **kwargs
        )

    def login(self):
        super(WeConnectSession, self).login()
        auth_url = self.authorizationUrl(url='https://identity.vwgroup.io/oidc/v1/authorize')
        response = self.doWebAuth(auth_url)
        self.fetchTokens('https://identity.vwgroup.io/oidc/v1/token',
                         authorization_response=response
                         )

    def refresh(self):
        """Perform full re-login since OIDC hybrid flow does not issue refresh tokens.

        The hybrid flow (response_type=code id_token token) delivers tokens
        directly in the callback URL with no refresh_token for security
        reasons. When the access_token expires, we must do a complete
        re-authentication.
        """
        LOG.info('No refresh token available (OIDC hybrid flow). Performing full re-login.')
        self.login()

    def clearTokens(self) -> None:
        """
        Clear all stored tokens to force a fresh login.
        
        This method is useful when the server requests new authorization
        and we need to clear invalid/expired tokens.
        """
        LOG.info("Clearing all stored tokens")
        self.token = None
        LOG.debug("All tokens cleared successfully")

    def fetchTokens(
        self,
        token_url,
        authorization_response=None,
        **kwargs
    ):
        """Extract tokens from OIDC hybrid flow callback URL.

        With hybrid flow (response_type=code id_token token), the OAuth
        callback URL already contains access_token and id_token directly.
        No server-side token exchange is needed because Auth0 binds the
        authorization code to the CARIAD BFF as the authorized exchanger —
        a direct POST to identity.vwgroup.io/oidc/v1/token would return
        401 access_denied.

        This follows the same approach as robinostlund/volkswagencarnet#333.
        """
        self.parseFromFragment(authorization_response)

        if self.token is None:
            raise TemporaryAuthentificationError('Failed to parse tokens from authorization response')

        if 'access_token' not in self.token:
            raise TemporaryAuthentificationError(
                'No access token found in authorization response. '
                'The OIDC hybrid flow callback did not return an access token.'
            )

        LOG.info('Successfully obtained tokens from OIDC hybrid flow callback')
        LOG.debug('Access token expires in: %s seconds', self.token.get('expires_in', 'unknown'))

        # OIDC hybrid flow does not return refresh_token for security
        # reasons. Re-login will be required when the access_token expires.
        if 'refresh_token' not in self.token:
            LOG.debug('No refresh token in response (expected with hybrid flow)')

        return self.token

    def parseFromBody(self, token_response, state=None):
        try:
            token = json.loads(token_response)
        except json.decoder.JSONDecodeError:
            raise TemporaryAuthentificationError('Token could not be refreshed due to temporary WeConnect failure: json could not be decoded')
        if 'accessToken' in token:
            token['access_token'] = token.pop('accessToken')
        if 'idToken' in token:
            token['id_token'] = token.pop('idToken')
        if 'refreshToken' in token:
            token['refresh_token'] = token.pop('refreshToken')
        fixedTokenresponse = to_unicode(json.dumps(token)).encode("utf-8")
        parsedToken = super(WeConnectSession, self).parseFromBody(token_response=fixedTokenresponse, state=state)
        # Ensure the token is stored in the session object
        self.token = parsedToken
        return parsedToken

    def refreshTokens(
        self,
        token_url,
        refresh_token=None,
        auth=None,
        timeout=None,
        headers=None,
        verify=True,
        proxies=None,
        **kwargs
    ):
        """Token refresh is not available with OIDC hybrid flow.

        The hybrid flow does not return a refresh_token — Auth0 issues no
        refresh tokens for security reasons with response_type=code id_token
        token. When tokens expire, a full re-login is required.
        """
        LOG.info('Token refresh not available (OIDC hybrid flow). Performing full re-login.')
        self.login()
        return self.token
