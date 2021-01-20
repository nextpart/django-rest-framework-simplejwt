import jwt
from django.utils.translation import gettext_lazy as _
from jwt import InvalidAlgorithmError, InvalidTokenError, algorithms
from jwt import PyJWKClient
from jwt.api_jwt import decode_complete

from .exceptions import TokenBackendError
from .utils import format_lazy

ALLOWED_ALGORITHMS = (
    "HS256",
    "HS384",
    "HS512",
    "RS256",
    "RS384",
    "RS512",
)


class RemoteSetting:

    url_suffixes = {"KEYCLOAK": "/protocol/openid-connect/certs"}

    @classmethod
    def from_remote(cls, remote, remote_type="KEYCLOAK"):
        """Get the realm settings from remote."""
        try:
            suffix = cls.url_suffixes[remote_type]
        except KeyError as exc:
            raise TokenBackendError(
                _(f"Remote_Type is unknown: {remote_type}")
            ) from exc
        url = remote + suffix
        return PyJWKClient(url).get_signing_keys()


class TokenBackend:
    def __init__(
        self,
        algorithm,
        signing_key=None,
        verifying_key=None,
        audience=None,
        issuer=None,
        remotes=None,
        remote_type=None,
    ):
        self._validate_algorithm(algorithm)

        self.algorithm = algorithm
        self.signing_key = signing_key
        self.audience = audience
        self.issuer = issuer
        if algorithm.startswith("HS"):
            self.verifying_key = signing_key
        else:
            self.verifying_key = verifying_key
        self.remote_keys = None
        self.remote_type = remote_type
        if remotes is not None:
            if isinstance(remotes, list):
                self.remote_keys = {
                    remote: RemoteSetting.from_remote(remote, remote_type)
                    for remote in remotes
                }
            elif isinstance(remotes, str):
                self.remote_keys = {
                    remotes: RemoteSetting.from_remote(remotes, remote_type)
                }
            else:
                raise TokenBackendError(_("Invalid type for remotes setting"))

    def _validate_algorithm(self, algorithm):
        """
        Ensure that the nominated algorithm is recognized, and that cryptography is installed for those
        algorithms that require it
        """
        if algorithm not in ALLOWED_ALGORITHMS:
            raise TokenBackendError(
                format_lazy(_("Unrecognized algorithm type '{}'"), algorithm)
            )

        if algorithm in algorithms.requires_cryptography and not algorithms.has_crypto:
            raise TokenBackendError(
                format_lazy(
                    _("You must have cryptography installed to use {}."),
                    algorithm,
                )
            )

    def encode(self, payload):
        """
        Returns an encoded token for the given payload dictionary.
        """
        jwt_payload = payload.copy()
        if self.audience is not None:
            jwt_payload["aud"] = self.audience
        if self.issuer is not None:
            jwt_payload["iss"] = self.issuer

        token = jwt.encode(jwt_payload, self.signing_key, algorithm=self.algorithm)
        if isinstance(token, bytes):
            # For PyJWT <= 1.7.1
            return token.decode("utf-8")
        # For PyJWT >= 2.0.0a1
        return token

    def decode(self, token, options=None, verifying_key=None):
        """
        Performs a validation of the given token and returns its payload
        dictionary.

        Raises a `TokenBackendError` if the token is malformed, if its
        signature check fails, or if its 'exp' claim indicates it has expired.
        """
        verifying_key = self.verifying_key
        # verify with remote
        if self.remote_keys is not None:
            # token needed to fetch correct key for validation
            if options.get("verify_signature", True):
                verifying_key = self._get_remote_key(token)
        return self._decode(token, options, verifying_key)

    def _decode(self, token, options, verifying_key):
        try:
            if options is None:
                options = {}
            if "verify_signature" not in options:
                options["verify_signature"] = True
            if "verify_aud" not in options:
                options["verify_aud"] = self.audience is not None
            return jwt.decode(
                token,
                verifying_key,
                algorithms=[self.algorithm],
                audience=self.audience,
                issuer=self.issuer,
                options=options,
            )
        except InvalidAlgorithmError as ex:
            raise TokenBackendError(_("Invalid algorithm specified")) from ex
        except InvalidTokenError as ex:
            raise TokenBackendError(_("Token is invalid or expired")) from ex
        except Exception as ex:
            raise TokenBackendError(_("Unknown Exception ")) from ex

    def _get_remote_key(self, token):
        decoded_jwt = decode_complete(token, options={"verify_signature": False})
        try:
            kid = decoded_jwt["header"]["kid"]
            remote = decoded_jwt["payload"]["iss"]
        except KeyError as exc:
            raise TokenBackendError(
                _("Token did not contain expected remote information.")
            ) from exc
        if remote and remote in self.remote_keys:
            keys = self.remote_keys[remote]
        else:
            keys = RemoteSetting.from_remote(remote)
            self.remote_keys[remote] = keys
        verifying_keys = [key for key in keys if key.key_id == kid]
        if not verifying_keys:
            raise TokenBackendError(
                _(f"No matching remote key with kid = {kid} was found.")
            )
        if len(verifying_keys) != 1:
            raise TokenBackendError(
                _(f"Multiple matching remote key with kid = {kid} was found.")
            )
        return verifying_keys[0].key
