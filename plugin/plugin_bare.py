#
#   Copyright (c) 2025 One Identity
#

from safeguard.sessions.plugin import AAPlugin, AAResponse


class Plugin(AAPlugin):
    def _extract_mfa_password(self):
        return "can pass"

    def do_authenticate(self):
        self.session_cookie["IdentityProvider"] = self.plugin_configuration.get(
            "auth", "identity_provider"
        )
        gateway_user = self.connection.key_value_pairs.get(
            "sample_aa_plugin_gw_user_prompt"
        )
        gateway_password = self.connection.key_value_pairs.get(
            "sample_aa_plugin_gw_password_prompt"
        )
        if not gateway_user:
            return AAResponse.need_info(
                "Gateway user:", "sample_aa_plugin_gw_user_prompt"
            )

        if not gateway_password:
            return AAResponse.need_info(
                "Gateway password:",
                "sample_aa_plugin_gw_password_prompt",
                disable_echo=True,
            )

        self.logger.info(
            f"Set Identity Provider by plugin: {self.session_cookie['IdentityProvider']}"
        )
        self.logger.info(f"Set gateway user by plugin: '{gateway_user}'")
        if self._authenticate_user(gateway_user, gateway_password):
            return AAResponse.accept().with_gateway_user(gateway_user)
        else:
            return AAResponse.deny("Authentication failed.")

    def do_authorize(self):
        return AAResponse.accept("the reason to accept")

    def do_session_ended(self):
        pass

    @staticmethod
    def _authenticate_user(username, password):
        """
        This method should authenticate the user with the configured identity provider.
        You need to implement the actual authentication logic, ensuring secure verification of user credentials.
        """
        return bool(username and password)
