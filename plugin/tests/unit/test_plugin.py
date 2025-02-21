#
#   Copyright (c) 2025 One Identity
#

from ...plugin_bare import Plugin


def test_authenticate_accept_and_identity_provider_set():
    config = """
            [auth]
            identity_provider=test-identity-provider
            """

    parameters = {
        "cookie": {},
        "session_cookie": {},
        "session_id": "session-id",
        "protocol": "rdp",
        "connection_name": "test-connection",
        "client_ip": "1.2.3.4",
        "client_port": "3389",
        "client_hostname": "test-hostname",
        "gateway_user": "somebody",
        "gateway_domain": "test-domain",
        "server_username": "server-username",
        "server_domain": "test-server-domain",
        "key_value_pairs": {
            "sample_aa_plugin_gw_user_prompt": "somebody",
            "sample_aa_plugin_gw_password_prompt": "<PASSWORD>",
        },
    }

    result = Plugin(config).authenticate(**parameters)

    assert result["session_cookie"]["IdentityProvider"] == "test-identity-provider"
    assert result["verdict"] == "ACCEPT"


def test_authenticate_needinfo():
    config = ""

    parameters = {
        "cookie": {},
        "session_cookie": {},
        "session_id": "session-id",
        "protocol": "rdp",
        "connection_name": "test-connection",
        "client_ip": "1.2.3.4",
        "client_port": "3389",
        "client_hostname": "test-hostname",
        "gateway_user": "somebody",
        "gateway_domain": "test-domain",
        "server_username": "server-username",
        "server_domain": "test-server-domain",
        "key_value_pairs": {},
    }

    result = Plugin(config).authenticate(**parameters)

    assert result["verdict"] == "NEEDINFO"
