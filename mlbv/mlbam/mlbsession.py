"""
mlbsession
"""
import datetime
import io
import logging
import os
import random
import re
import string
import base64
import hashlib

import lxml
import lxml.etree
import pytz

import mlbv.mlbam.common.config as config
import mlbv.mlbam.common.util as util
import mlbv.mlbam.common.session as session

LOG = logging.getLogger(__name__)

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:66.0) "
    "Gecko/20100101 Firefox/66.0"
)

PLATFORM = "macintosh"
BAM_SDK_VERSION = "3.4"
MLB_API_KEY_URL = "https://www.mlb.com/tv/g490865/"
API_KEY_RE = re.compile(r'"x-api-key","value":"([^"]+)"')
CLIENT_API_KEY_RE = re.compile(r'"clientApiKey":"([^"]+)"')
OKTA_CLIENT_ID_RE = re.compile("""production:{clientId:"([^"]+)",""")
MLB_OKTA_URL = "https://www.mlbstatic.com/mlb.com/vendor/mlb-okta/mlb-okta.js"
AUTHN_URL = "https://ids.mlb.com/api/v1/authn"
OKTA_AUTHORIZE_URL = "https://ids.mlb.com/oauth2/aus1m088yK07noBfh356/v1/authorize"
OKTA_TOKEN_URL = "https://ids.mlb.com/oauth2/aus1m088yK07noBfh356/v1/token"
BAM_DEVICES_URL = "https://us.edge.bamgrid.com/devices"
BAM_SESSION_URL = "https://us.edge.bamgrid.com/session"
BAM_TOKEN_URL = "https://us.edge.bamgrid.com/token"
BAM_ENTITLEMENT_URL = "https://media-entitlement.mlb.com/api/v3/jwt"
GAME_CONTENT_URL_TEMPLATE = "http://statsapi.mlb.com/api/v1/game/{game_id}/content"
STREAM_URL_TEMPLATE = (
    "https://edge.svcs.mlb.com/media/{media_id}/scenarios/browser~csai"
)
MEDIA_GATEWAY_GRAPHQL_URL = "https://media-gateway.mlb.com/graphql"
AIRINGS_URL_TEMPLATE = (
    "https://search-api-mlbtv.mlb.com/svc/search/v2/graphql/persisted/query/"
    "core/Airings?variables={{%22partnerProgramIds%22%3A[%22{game_id}%22]}}"
)


def gen_random_string(n):
    return "".join(
        random.choice(string.ascii_uppercase + string.digits) for _ in range(n)
    )


class SGProviderLoginException(BaseException):
    """Flags that a login is required."""

    pass


# Notes on okta OIDC:
# https://developer.okta.com/blog/2017/07/25/oidc-primer-part-1
#
# Discover endpoints:
# https://ids.mlb.com/oauth2/aus1m088yK07noBfh356/.well-known/openid-configuration
#
class MLBSession(session.Session):
    """MLB Session handling"""

    def __init__(self):
        session.Session.__init__(self, USER_AGENT, PLATFORM)

    # Override
    def login(self):
        """Posts to the AUTHN_URL and saves the session token"""

        authn_params = {
            "username": config.CONFIG.parser["username"],
            "password": config.CONFIG.parser["password"],
            "options": {
                "multiOptionalFactorEnroll": False,
                "warnBeforePasswordExpired": True,
            },
        }
        LOG.debug("login: %s", authn_params["username"])
        authn_response = self.session.post(AUTHN_URL, json=authn_params).json()
        LOG.debug("login: authn_response: %s", authn_response)
        self.session_token = authn_response["sessionToken"]
        self._state["session_token_time"] = str(datetime.datetime.now(tz=pytz.UTC))
        self.save()

    # Override
    def _refresh_access_token(self, clear_token=False):
        """Update API keys"""

        if clear_token:
            self.session_token = None

        LOG.debug("Updating MLB api keys")
        content = self.session.get(MLB_API_KEY_URL).text
        if config.VERBOSE:
            LOG.debug("MLB api keys: %s", content)
        parser = lxml.etree.HTMLParser()
        data = lxml.etree.parse(io.StringIO(content), parser)

        # API key
        scripts = data.xpath(".//script")
        for script in scripts:
            if script.text and "x-api-key" in script.text:
                self._state["api_key"] = API_KEY_RE.search(script.text).groups()[0]
            if script.text and "clientApiKey" in script.text:
                self._state["client_api_key"] = CLIENT_API_KEY_RE.search(
                    script.text
                ).groups()[0]

        LOG.debug("Updating Okta api keys")
        content = self.session.get(MLB_OKTA_URL).text
        self._state["okta_client_id"] = OKTA_CLIENT_ID_RE.search(content).groups()[0]
        LOG.debug("okta_client_id: %s", self._state["okta_client_id"])

        # OKTA Code
        def get_okta_code():
            state_param = gen_random_string(64)
            nonce_param = gen_random_string(64)

            self.code_verifier = gen_random_string(58)
            self.code_challenge = base64.urlsafe_b64encode(hashlib.sha256(self.code_verifier.encode('ascii')).digest()).decode('ascii')[:-1]

            authz_params = {
                "client_id": self._state["okta_client_id"],
                "redirect_uri": "https://www.mlb.com/login",
                "response_type": "code",
                "response_mode": "okta_post_message",
                "state": state_param,
                "nonce": nonce_param,
                "prompt": "none",
                "sessionToken": self.session_token,  # may trigger login
                "scope": "openid email",
                "code_challenge": self.code_challenge,
                "code_challenge_method": "S256",
            }
        
            authz_response = self.session.get(OKTA_AUTHORIZE_URL, params=authz_params)
            authz_content = authz_response.text

            if config.VERBOSE:
                LOG.debug("get_okta_code reponse: %s", authz_content)
            for line in authz_content.split("\n"):
                if "data.code" in line:
                    return line.split("'")[1].encode("utf-8").decode("unicode_escape")
                if "data.error = 'login_required'" in line:
                    raise SGProviderLoginException
            LOG.debug("get_okta_code failed: %s", authz_content)
            raise Exception("could not authenticate: {authz_content}")

        # OKTA Token
        def get_okta_token():
            token_data = {
                "client_id": self._state["okta_client_id"],
                "redirect_uri": "https://www.mlb.com/login",
                "grant_type": "authorization_code",
                "code_verifier": self.code_verifier,
                "code": self.okta_access_code,
            }

            token_headers = {
                "Accept": "application/json",
                "Content-type": "application/x-www-form-urlencoded",
            }

            token_response = self.session.post(
                OKTA_TOKEN_URL, headers=token_headers, data=token_data
            ).json()

            if config.VERBOSE:
                LOG.debug("get_okta_token reponse: %s", token_response)

            if "access_token" in token_response:
                return token_response["access_token"]
            else:
                LOG.error("No access_token in token response")
                LOG.debug("No access_token in token response: %s", token_response.text)

                raise Exception("could not authenticate: {token_response}")

        try:
            self.okta_access_code = get_okta_code()
        except SGProviderLoginException:
            # not logged in -- get session token and try again
            self.login()
            self.okta_access_code = get_okta_code()

        assert self.okta_access_code is not None

        try:
            self._state["OKTA_ACCESS_TOKEN"] = get_okta_token()
        except SGProviderLoginException:
            # not logged in -- get session token and try again
            self.login()
            self._state["OKTA_ACCESS_TOKEN"] = get_okta_token()

        assert self._state["OKTA_ACCESS_TOKEN"] is not None

        # Device Assertion
        devices_headers = {
            "Authorization": "Bearer %s" % (self.client_api_key),
            "Origin": "https://www.mlb.com",
        }

        devices_params = {
            "applicationRuntime": "firefox",
            "attributes": {},
            "deviceFamily": "browser",
            "deviceProfile": "macosx",
        }

        devices_response = self.session.post(
            BAM_DEVICES_URL, headers=devices_headers, json=devices_params
        ).json()

        # Issue #53: no assertion key here:
        if "assertion" in devices_response:
            devices_assertion = devices_response["assertion"]
        else:
            devices_assertion = None
            LOG.error("No assertion key in devices response")
            LOG.debug("No assertion key in devices response: %s", devices_response.text)

        # Device token
        token_params = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "latitude": "0",
            "longitude": "0",
            "platform": "browser",
            "subject_token": devices_assertion,
            "subject_token_type": "urn:bamtech:params:oauth:token-type:device",
        }
        token_response = self.session.post(
            BAM_TOKEN_URL, headers=devices_headers, data=token_params
        ).json()

        device_access_token = token_response["access_token"]

        # # Create session
        # session_headers = {
        #     "Authorization": device_access_token,
        #     "User-agent": USER_AGENT,
        #     "Origin": "https://www.mlb.com",
        #     "Accept": "application/vnd.session-service+json; version=1",
        #     "Accept-Encoding": "gzip, deflate, br",
        #     "Accept-Language": "en-US,en;q=0.5",
        #     "x-bamsdk-version": BAM_SDK_VERSION,
        #     "x-bamsdk-platform": PLATFORM,
        #     "Content-type": "application/json",
        #     "TE": "Trailers",
        # }
        # session_response = self.session.get(
        #     BAM_SESSION_URL, headers=session_headers
        # ).json()
        # import ipdb; ipdb.set_trace()
        # device_id = session_response["device"]["id"]

        device_id, session_id = self._create_session()

        # Entitlement token
        entitlement_params = {"os": PLATFORM, "did": device_id, "appname": "mlbtv_web"}

        entitlement_headers = {
            "Authorization": "Bearer %s" % (self._state["OKTA_ACCESS_TOKEN"]),
            "Origin": "https://www.mlb.com",
            # TODO: is api_key correct?  always None?
            "x-api-key": self._state["api_key"],
        }
        entitlement_response = self.session.get(
            BAM_ENTITLEMENT_URL, headers=entitlement_headers, params=entitlement_params
        )

        entitlement_token = entitlement_response.content

        # Get access token
        headers = {
            "Authorization": "Bearer %s" % self._state["client_api_key"],
            "User-agent": USER_AGENT,
            "Accept": "application/vnd.media-service+json; version=1",
            "x-bamsdk-version": BAM_SDK_VERSION,
            "x-bamsdk-platform": PLATFORM,
            "origin": "https://www.mlb.com",
        }
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "platform": "browser",
            "subject_token": entitlement_token,
            "subject_token_type": "urn:bamtech:params:oauth:token-type:account",
        }
        response = self.session.post(BAM_TOKEN_URL, data=data, headers=headers)
        # from requests_toolbelt.utils import dump
        # print(dump.dump_all(response).decode("utf-8"))
        response.raise_for_status()
        token_response = response.json()
        if config.VERBOSE:
            LOG.debug("token_response: %s", token_response)

        # Finally: update the token and expiry in our _state:
        self._state["access_token_expiry"] = str(
            datetime.datetime.now(tz=pytz.UTC)
            + datetime.timedelta(seconds=token_response["expires_in"])
        )
        self._state["access_token"] = token_response["access_token"]
        self.save()

    def get_game_content(self, game_pk):
        self._refresh_access_token()

        headers = {

            "Authorization": f"Bearer {self._state['OKTA_ACCESS_TOKEN']}",
            "User-agent": USER_AGENT,
            #            "Accept": "application/vnd.media-service+json; version=1",
            "x-bamsdk-version": BAM_SDK_VERSION,
            "x-bamsdk-platform": PLATFORM,
            "origin": "https://www.mlb.com",
        }

        content_search_op = {
            "operationName": "contentSearch",
            "query": "query contentSearch($query: String!, $limit: Int = 10, $skip: Int = 0) {\n    contentSearch(\n        query: $query\n        limit: $limit\n        skip: $skip\n    ) {\n        total\n        content {\n            audioTracks {\n                language\n                name\n                renditionName\n                trackType\n            }\n            contentId\n            mediaId\n            contentType\n            contentRestrictions\n            contentRestrictionDetails {\n                code\n                details\n            }\n            sportId\n            feedType\n            callSign\n            mediaState {\n                state\n                mediaType\n                contentExperience\n            }\n            fields {\n                name\n                value\n            }\n            milestones {\n                milestoneType\n                relativeTime\n                absoluteTime\n                title\n                keywords {\n                    name\n                    value\n                }\n            }\n        }\n    }\n  }",
            "variables": {
                "limit": 16,
                "query": f"GamePk={game_pk} AND ContentType=\"GAME\" RETURNING HomeTeamId, HomeTeamName, AwayTeamId, AwayTeamName, Date, MediaType, ContentExperience, MediaState, PartnerCallLetters"
            }
        }

        r = self.session.post(MEDIA_GATEWAY_GRAPHQL_URL, json=content_search_op, headers=headers)
        j = r.json()
        # print(j)
        r.raise_for_status()

        return j['data']['contentSearch']['content']

    # Override
    def lookup_stream_url(self, game_pk, media_id):
        """game_pk: game_pk
        media_id: mediaPlaybackId
        """
        stream_url = None

        self._refresh_access_token()

        headers = {

            "Authorization": f"Bearer {self._state['OKTA_ACCESS_TOKEN']}",
            "User-agent": USER_AGENT,
#            "Accept": "application/vnd.media-service+json; version=1",
            "x-bamsdk-version": BAM_SDK_VERSION,
            "x-bamsdk-platform": PLATFORM,
            "origin": "https://www.mlb.com",
        }

        device_id, session_id = self._create_session()

        # playback session
        playback_session_op = {
            "operationName": "initPlaybackSession",
            "query": "mutation initPlaybackSession(\n        $adCapabilities: [AdExperienceType]\n        $mediaId: String!\n        $deviceId: String!\n        $sessionId: String!\n        $quality: PlaybackQuality\n    ) {\n        initPlaybackSession(\n            adCapabilities: $adCapabilities\n            mediaId: $mediaId\n            deviceId: $deviceId\n            sessionId: $sessionId\n            quality: $quality\n        ) {\n            playbackSessionId\n            playback {\n                url\n                token\n                expiration\n                cdn\n            }\n            adScenarios {\n                adParamsObj\n                adScenarioType\n                adExperienceType\n            }\n            adExperience {\n                adExperienceTypes\n                adEngineIdentifiers {\n                    name\n                    value\n                }\n                adsEnabled\n            }\n            heartbeatInfo {\n                url\n                interval\n            }\n            trackingObj\n        }\n    }",
            "variables": {
                "adCapabilities": ["GOOGLE_STANDALONE_AD_PODS"],
                "deviceId": device_id,
                "mediaId": media_id,
                "quality": "PLACEHOLDER",
                "sessionId": session_id
            }
        }

        response = self.session.post(MEDIA_GATEWAY_GRAPHQL_URL, json=playback_session_op, headers=headers)

        if response is not None and config.SAVE_JSON_FILE:
            output_filename = "stream"
            json_file = os.path.join(
                util.get_tempdir(), "{}.json".format(output_filename)
            )
            with open(json_file, "w") as out:  # write date to json_file
                out.write(response.text)

        stream = response.json()
        LOG.debug("lookup_stream_url, stream response: %s", stream)
        if "errors" in stream and stream["errors"]:
            LOG.error("Could not load stream\n%s", stream)
            return None
        stream_url = stream['data']['initPlaybackSession']['playback']['url']
        return stream_url

    def _create_session(self):
        headers = {

            "Authorization": f"Bearer {self._state['OKTA_ACCESS_TOKEN']}",
            "User-agent": USER_AGENT,
            #            "Accept": "application/vnd.media-service+json; version=1",
            "x-bamsdk-version": BAM_SDK_VERSION,
            "x-bamsdk-platform": PLATFORM,
            "origin": "https://www.mlb.com",
        }

        # Init session
        init_session_op = {
            "operationName": "initSession",
            "query": "mutation initSession($device: InitSessionInput!, $clientType: ClientType!, $experience: ExperienceTypeInput) {\n    initSession(device: $device, clientType: $clientType, experience: $experience) {\n        deviceId\n        sessionId\n        entitlements {\n            code\n        }\n        location {\n            countryCode\n            regionName\n            zipCode\n            latitude\n            longitude\n        }\n        clientExperience\n        features\n    }\n  }",
            "variables": {
                "device": {},
                "clientType": "WEB"
            }
        }

        r = self.session.post(MEDIA_GATEWAY_GRAPHQL_URL, json=init_session_op, headers=headers)
        j = r.json()
        # print(j)
        r.raise_for_status()

        session = j['data']['initSession']
        return session['deviceId'], session['sessionId']
